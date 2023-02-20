import sys, os, asyncio, logging, time, weakref, re
from base64 import b32encode, b64decode, b64encode
from binascii import b2a_hex, a2b_hex
from aiohttp import web
from hashlib import sha256
from utils import pformat_json, json_loads, json_dumps, cleanup_psbt
from aiohttp.web_exceptions import HTTPMovedPermanently, HTTPNotFound, HTTPBadRequest, HTTPFound
from conn import Connection, MissingColdcard
from status import STATUS
from persist import Settings, settings, BP
import time

from ckcc.protocol import CCProtocolPacker
from ckcc.constants import USER_AUTH_TOTP, USER_AUTH_HMAC, USER_AUTH_SHOW_QR, MAX_USERNAME_LEN
from ckcc.constants import STXN_VISUALIZE, STXN_SIGNED, AF_P2WPKH, AF_CLASSIC
from ckcc.protocol import CCUserRefused
import policy

routes = web.RouteTableDef()
web_sockets = weakref.WeakSet()

APPROVE_CTA = '''\
Please consult the Coldcard screen and review the HSM policy shown there. If you \
are satisfied it does what you need, approve the policy and the Coldcard will enter HSM mode.
'''

HSM_MODE = "Coldcard now in HSM mode"

async def push_status_updates_handler(ws):
    # block for a bit, and then send display updates (and all other system status changes)

    # - there is no need for immediate update because when we rendered the HTML on page
    #   load, we put in current values.
    await asyncio.sleep(0.250)

    last = None
    while 1:
        # get latest state
        now = STATUS.as_dict()

        if last != now:
            # it has changed, so send it.
            try:
                await ws.send_str(json_dumps(dict(update_status=now)))
            except ConnectionResetError:
                break
            last = now

        # wait until next update, or X seconds max (for keep alive/just in case)
        try:
            await asyncio.wait_for(STATUS._update_event.wait(), 120)
        except asyncio.TimeoutError:
            # force an update
            last = None

@routes.get('/websocket')
async def api_websocket(request):
    '''
        Stream display activity as HTML fragments
        - accept config changes
        - and more?
    '''

    # begin a streaming response
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    web_sockets.add(ws)

    try:
        api_rx = asyncio.create_task(rx_handler(ws, request))
        dis_tx = asyncio.create_task(push_status_updates_handler(ws))

        await asyncio.gather(api_rx, dis_tx)
    finally:
        api_rx.cancel()
        dis_tx.cancel()
        await ws.close()

    return ws

async def rx_handler(ws, orig_request):
    # Block on receive, handle each message as it comes in.
    # see pp/aiohttp/client_ws.py

    async def tx_resp(_ws=ws, **resp):
        logging.debug(f"Send resp: {resp}")
        await _ws.send_str(json_dumps(resp))


    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                raise TypeError('expected text')

            try:
                assert len(msg.data) < 20000
                req = json_loads(msg.data)

                if '_ping' in req:
                    # connection keep alive, simple
                    await tx_resp(_pong=1)
                    continue

                # Caution: lots of sensitive values here XXX
                #logging.info("WS api data: %r" % req)

            except Exception as e:
                logging.critical("Junk data on WS", exc_info=1)
                break # the connection

            # do something with the request
            failed = True
            try:
                await ws_api_handler(tx_resp, req, orig_request)
                failed = False
            except SystemExit:
                raise
            except KeyboardInterrupt:
                break
            except ValueError as exc:
                # pre-formated text for display
                msg = exc.args[0]
            except RuntimeError as exc:
                # covers CCProtoError and similar
                msg = str(exc) or str(type(exc).__name__)
            except BaseException as exc:
                logging.exception("API fail: req=%r" % req)
                msg = str(exc) or str(type(exc).__name__)

            if failed:
                # standard error response
                await tx_resp(error=msg)
    except ConnectionResetError:
        logging.info("Breaking rx_handler")
        pass

async def ws_api_handler(send_json, req, orig_request):     # handle_api
    #
    # Handle incoming requests over websocket; send back results.
    # req = already json parsed request coming in
    # send_json() = means to send the response back
    #
    action = req.action
    args = getattr(req, 'args', None)

    #logging.warn("API action=%s (%r)" % (action, args))        # MAJOR info leak XXX
    logging.debug(f"API action={action}")

    if action == '_connected':
        logging.info("Websocket connected: %r" % args)

        # can send special state update at this point, depending on the page

    elif action == 'start_hsm_btn':
        await Connection().hsm_start()
        await send_json(show_flash_msg=APPROVE_CTA)

    elif action == 'delete_user':
        name, = args
        assert 1 <= len(name) <= MAX_USERNAME_LEN, "bad username length"
        await Connection().delete_user(name.encode('utf8'))

        # assume it worked, so UX updates right away
        try:
            STATUS.hsm.users.remove(name)
        except ValueError:
            pass
        STATUS.notify_watchers()

    elif action == 'create_user':
        name, authmode, new_pw = args

        assert 1 <= len(name) <= MAX_USERNAME_LEN, "bad username length"
        assert ',' not in name, "no commas in names"

        if authmode == 'totp':
            mode = USER_AUTH_TOTP | USER_AUTH_SHOW_QR
            new_pw = ''
        elif authmode == 'rand_pw':
            mode = USER_AUTH_HMAC | USER_AUTH_SHOW_QR
            new_pw = ''
        elif authmode == 'give_pw':
            mode = USER_AUTH_HMAC
        else:
            raise ValueError(authmode)

        await Connection().create_user(name.encode('utf8'), mode, new_pw)

        # assume it worked, so UX updates right away
        try:
            STATUS.hsm.users = list(set(STATUS.hsm.users + [name]))
        except ValueError:
            pass
        STATUS.notify_watchers()

    elif action == 'submit_policy':
        # get some JSON w/ everything the user entered.
        p, save_copy = args

        proposed = policy.web_cleanup(json_loads(p))

        policy.update_sl(proposed)

        try:
            await Connection().hsm_start(proposed)
        except RuntimeError as e:
            await send_json(error=str(e))

        while 1:
            await asyncio.sleep(settings.PING_RATE)
            if STATUS.hsm['active']:
                break

        STATUS.notify_watchers()

        if save_copy:
            d = policy.desensitize(proposed)
            await send_json(local_download=dict(data=json_dumps(d, indent=2),
                                filename=f'hsm-policy-{STATUS.xfp}.json.txt'))


    elif action == 'download_policy':

        proposed = policy.web_cleanup(json_loads(args[0]))
        await send_json(local_download=dict(data=json_dumps(proposed, indent=2),
                                filename=f'hsm-policy-{STATUS.xfp}.json.txt'))

    elif action == 'import_policy':
        # they are uploading a JSON capture, but need values we can load in Vue
        proposed = args[0]
        cooked = policy.web_cookup(proposed)
        await send_json(vue_app_cb=dict(update_policy=cooked),
                        show_flash_msg="Policy file imported.")

    elif action == 'pick_master_pw':
        pw = b64encode(os.urandom(12)).decode('ascii')
        pw = pw.replace('/', 'S').replace('+', 'p')
        assert '=' not in pw

        await send_json(vue_app_cb=dict(new_master_pw=pw))

    elif action == 'new_bunker_config':
        # save and apply config values
        nv = json_loads(args[0])

        assert 4 <= len(nv.master_pw) < 200, "Master password must be at least 4 chars long"

        # copy in simple stuff
        for fn in [ 'master_pw', 'easy_captcha', 'allow_reboots']:
            if fn in nv:
                BP[fn] = nv[fn]

        BP.save()

        await send_json(show_flash_msg="Bunker settings encrypted and saved to disk.")

        STATUS.notify_watchers()

    elif action == 'sign_message':
        # sign a short text message
        # - lots more checking could be done here, but CC does it anyway
        msg_text, path, addr_fmt = args

        addr_fmt = AF_P2WPKH if addr_fmt != 'classic' else AF_CLASSIC

        try:
            sig, addr = await Connection().sign_text_msg(msg_text, path, addr_fmt)
        except:
            # get the spinner to stop: error msg will be "refused by policy" typically
            await send_json(vue_app_cb=dict(msg_signing_result='(failed)'))
            raise

        sig = b64encode(sig).decode('ascii').replace('\n', '')

        await send_json(vue_app_cb=dict(msg_signing_result=f'{sig}\n{addr}'))

    elif action == 'upload_psbt':
        # receiving a PSBT for signing

        size, digest, contents = args
        psbt = b64decode(contents)
        assert len(psbt) == size, "truncated/padded in transit"
        assert sha256(psbt).hexdigest() == digest, "corrupted in transit"

        STATUS.import_psbt(psbt)
        STATUS.notify_watchers()

        await send_json(success=f"Server successfully imported psbt {digest}")

    elif action == 'clear_psbt':
        STATUS.clear_psbt()
        STATUS.notify_watchers()

    elif action == 'preview_psbt':
        STATUS.psbt_preview = 'Wait...'
        STATUS.notify_watchers()
        try:
            txt = await Connection().sign_psbt(STATUS._pending_psbt, flags=STXN_VISUALIZE)
            txt = txt.decode('ascii')
            # force some line splits, especially for bech32, 32-byte values (p2wsh)
            probs = re.findall(r'([a-zA-Z0-9]{36,})', txt)
            for p in probs:
                txt = txt.replace(p, p[0:30] + '\u22ef\n\u22ef' + p[30:])
            STATUS.psbt_preview = txt
        except:
            # like if CC doesn't like the keys, whatever ..
            STATUS.psbt_preview = None
            raise
        finally:
            STATUS.notify_watchers()

    elif action == 'auth_set_name':
        idx, name = args

        assert 0 <= len(name) <= MAX_USERNAME_LEN
        assert 0 <= idx < len(STATUS.pending_auth)

        STATUS.pending_auth[idx].name = name
        STATUS.notify_watchers()

    elif action == 'auth_offer_guess':
        idx, ts, guess = args
        assert 0 <= idx < len(STATUS.pending_auth)
        STATUS.pending_auth[idx].totp = ts
        STATUS.pending_auth[idx].has_guess = 'x'*len(guess)
        STATUS._auth_guess[idx] = guess
        STATUS.notify_watchers()

    elif action == 'submit_psbt':
        # they want to sign it now
        expect_hash, send_immediately, finalize, wants_dl = args

        assert expect_hash == STATUS.psbt_hash, "hash mismatch"
        if send_immediately: assert finalize, "must finalize b4 send"

        logging.info("Starting to sign...")
        STATUS.busy_signing = True
        STATUS.notify_watchers()

        try:
            dev = Connection()

            # do auth steps first (no feedback given)
            # for pa, guess in zip(STATUS.pending_auth, STATUS._auth_guess):
            #     if pa.name and guess:
            #         await dev.user_auth(pa.name, guess, int(pa.totp), a2b_hex(STATUS.psbt_hash))

            # STATUS.reset_pending_auth()

            try:
                result = await dev.sign_psbt(STATUS._pending_psbt, finalize=finalize)
                logging.info("Done signing")

                result = (b2a_hex(result) if finalize else b64encode(result)).decode('ascii')
                fname = 'transaction.txt' if finalize else ('signed-%s.psbt'%STATUS.psbt_hash[-6:])

                if wants_dl:
                    await send_json(local_download=dict(data=result, filename=fname,
                                                        is_b64=(not finalize)))

                await dev.hsm_status()
            except CCUserRefused:
                logging.error("Coldcard refused to sign txn")
                await dev.hsm_status()
                r = STATUS.hsm.get('last_refusal', None)
                if not r:
                    raise ValueError('Refused by local user.')
                else:
                    raise ValueError(f"Rejected by Coldcard.<br><br>{r}")

        finally:
            STATUS.busy_signing = False
            STATUS.notify_watchers()

    elif action == 'shutdown_bunker':
        await send_json(show_flash_msg="Bunker is shutdown.")
        await asyncio.sleep(0.25)
        logging.warn("User-initiated shutdown")
        asyncio.get_running_loop().stop()
        sys.exit(0)

    elif action == 'leave_setup_mode':
        assert STATUS.setup_mode, 'not in setup mode?'

        STATUS.setup_mode = False

        STATUS.notify_watchers()


    else:
        raise NotImplementedError(action)

async def startup():
    aws = []

    # Setup
    from utils import setup_logging
    setup_logging()

    STATUS.force_local_mode = True
    STATUS.setup_mode = False

    # Web
    app = web.Application()
    app.add_routes(routes)

    my_url = f"http://localhost:{settings.PORT_NUMBER}"
    logging.info(f"Web server at:    {my_url}")

    from aiohttp.abc import AbstractAccessLogger
    class AccessLogger(AbstractAccessLogger):
        def log(self, request, response, time):
            self.logger.info(f'{response.status} <= {request.method} {request.path}')
    run_web = web._run_app(app, port=settings.PORT_NUMBER, print=None, access_log_class=AccessLogger)

    # Connection to CC
    from conn import Connection
    dev = Connection(None).run()

    # Async processes
    aws.append(dev)
    aws.append(run_web)

    await asyncio.gather(*aws)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(startup())