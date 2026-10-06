# -*- coding: utf-8 -*-
"""
KySoPDF agent - ban viet lai cho Windows 7 (Python 3.8).
Chay:  python agent.py     (hoac KySoPDF.exe sau khi build)
Mo trinh duyet: http://127.0.0.1:8765
Giao thuc API giu nguyen nhu ban cu de dung lai index.html.
"""
import io
import json
import os
import sys
import threading
import time
import traceback
import webbrowser
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file, make_response

# ---------------------------------------------------------------- cau hinh
def base_dir():
    # Khi dong goi bang PyInstaller, file nam canh .exe
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE = base_dir()
DEFAULTS = {
    "pkcs11_lib": "auto",
    "port": 8765,
    "font_path": r"C:\Windows\Fonts\arial.ttf",
    "timestamp_url": "",
    "use_raw_mechanism": False,
    "stamp_show_dn": True,
    "open_browser": True,
    "open_url": "",
}


def load_config():
    cfg = dict(DEFAULTS)
    path = os.path.join(BASE, "config.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8-sig") as f:
            cfg.update(json.load(f))
    return cfg


CFG = load_config()

# Cac ten DLL PKCS#11 pho bien cua token CA tai Viet Nam (chua kiem chung het,
# neu khong tu tim thay thi dien duong dan DLL vao "pkcs11_lib" trong config.json)
CANDIDATE_DLLS = [
    "viettel-ca_v6.dll",     # Viettel-CA (uu tien)
    "viettel-ca_v5.dll",
    "viettel-ca.dll",
    "eTPKCS11.dll",          # SafeNet eToken (mot so token Viettel dung loai nay)
    "vnpt-ca_csp11.dll",     # VNPT-CA
    "VNPT-CA_v34.dll",
    "BkavCA.dll",            # Bkav
    "eps2003csp11.dll",      # ePass2003 (Feitian)
    "ShuttleCsp11_3003.dll", # CA2
    "SignatureP11.dll",      # FPT-CA
    "ngp11v211.dll",
    "wdpkcs.dll",            # WatchData
    "cmp11.dll",
    "asepkcs.dll",
    "OcsPKCS11.dll",
]


def candidate_paths():
    """Tra ve danh sach moi DLL PKCS#11 co the dung (theo thu tu uu tien)."""
    cfg_path = CFG.get("pkcs11_lib", "auto")
    if cfg_path and cfg_path.lower() != "auto":
        return [cfg_path] if os.path.exists(cfg_path) else []
    import glob
    windir = os.environ.get("WINDIR", r"C:\Windows")
    folders = [os.path.join(windir, "System32"), os.path.join(windir, "SysWOW64")]
    result = []
    for folder in folders:
        for name in CANDIDATE_DLLS:
            p = os.path.join(folder, name)
            if os.path.exists(p):
                result.append(p)
    # DLL Viettel o System32/SysWOW64 va thu muc Token Agent/Token Manager
    pf = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]
    for folder in folders:
        result += sorted(glob.glob(os.path.join(folder, "*viettel*.dll")))
    for base in pf:
        if base:
            result += sorted(glob.glob(os.path.join(base, "Viettel*", "viettel*.dll")), reverse=True)
    seen, out = set(), []
    for p in result:
        k = os.path.normcase(p)
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def probe(path):
    """Nap DLL va dem so token dang cam. Tra ve (so_token, thong_bao_loi)."""
    import pkcs11
    try:
        lib = pkcs11.lib(path)
        return len(list(lib.get_slots(token_present=True))), None
    except Exception as e:
        return 0, str(e)


_LIB_CACHE = {}


def find_pkcs11_lib():
    """Chon DLL dau tien thay token; neu khong DLL nao thay thi tra ve DLL dau tien."""
    cands = candidate_paths()
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    cached = _LIB_CACHE.get("path")
    if cached and cached in cands:
        n, _ = probe(cached)
        if n:
            return cached
    for p in cands:
        n, _ = probe(p)
        if n:
            _LIB_CACHE["path"] = p
            return p
    return cands[0]


# ---------------------------------------------------------------- app
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
TOKEN_LOCK = threading.Lock()  # PKCS#11 khong an toan da luong
PORT = int(CFG["port"])
ALLOWED_HOSTS = {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT}


@app.before_request
def guard():
    # Chan trang web la goi vao agent (de lo PIN / ky trom) va DNS-rebinding.
    host = request.headers.get("Host", "")
    if host not in ALLOWED_HOSTS:
        return jsonify(error="Host khong hop le."), 403
    origin = request.headers.get("Origin")
    if origin:
        ok = {"http://" + h for h in ALLOWED_HOSTS} | set(CFG.get("allowed_origins", []))
        if origin not in ok:
            return jsonify(error="Nguon goi khong duoc phep."), 403


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
    return resp


def err(msg, code=400):
    return jsonify(error=msg), code


@app.route("/")
def index():
    p = os.path.join(BASE, "index.html")
    if not os.path.exists(p):
        return ("Thieu file index.html canh agent. Hay chep index.html vao thu muc: " + BASE, 500)
    return send_file(p, mimetype="text/html")


@app.route("/api/status")
def status():
    return jsonify(ok=True, version="win7-1.0")


# ---------------------------------------------------------------- PKCS#11
def open_lib():
    import pkcs11
    path = find_pkcs11_lib()
    if not path:
        raise RuntimeError(
            "Khong tim thay thu vien PKCS#11 cua token. Cai driver token, hoac ghi duong dan "
            "file DLL vao muc pkcs11_lib trong config.json.")
    return pkcs11.lib(path), path


def iter_certs(lib):
    """Duyet moi slot co token, tra ve (slot, token, cert_obj) khong can PIN."""
    from pkcs11 import Attribute, ObjectClass
    for slot in lib.get_slots(token_present=True):
        token = slot.get_token()
        with token.open() as session:
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                yield slot, token, obj


def parse_cert(obj):
    from pkcs11 import Attribute
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    der = bytes(obj[Attribute.VALUE])
    cert = x509.load_der_x509_certificate(der)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string()
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        cid = bytes(obj[Attribute.ID])
    except Exception:
        cid = b""
    try:
        label = obj[Attribute.LABEL] or ""
    except Exception:
        label = ""
    return {
        "id": cid.hex(),
        "label": label,
        "cn": cn,
        "not_after": not_after.isoformat(),
        "expired": not_after < datetime.now(timezone.utc),
    }


@app.route("/api/certs")
def certs():
    with TOKEN_LOCK:
        try:
            lib, _ = open_lib()
            out, seen = [], set()
            for _slot, _token, obj in iter_certs(lib):
                c = parse_cert(obj)
                key = (c["id"], c["label"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(c)
            return jsonify(certs=out)
        except Exception as e:
            traceback.print_exc()
            return err(str(e), 500)


@app.route("/api/diagnose")
def diagnose():
    steps = []

    def add(ok, name, detail):
        steps.append({"ok": ok, "name": name, "detail": detail})

    add(True, "Agent", "Dang chay (Python %s)." % sys.version.split()[0])
    path = find_pkcs11_lib()
    if not path:
        add(False, "Thu vien token", "Khong thay file DLL PKCS#11. Cai driver token hoac dien pkcs11_lib trong config.json.")
        return jsonify(steps=steps)
    add(True, "Thu vien token", path)
    with TOKEN_LOCK:
        import struct
        add(True, "Python", "%d-bit. DLL token phai cung %d-bit." % (struct.calcsize("P") * 8, struct.calcsize("P") * 8))
        for p in candidate_paths():
            n, e = probe(p)
            if e:
                add(False, "Thu DLL", "%s -> loi nap: %s" % (p, e))
            else:
                add(n > 0, "Thu DLL", "%s -> thay %d token" % (p, n))
        try:
            import pkcs11
            lib = pkcs11.lib(path)
            add(True, "Nap thu vien", "Nap DLL thanh cong.")
        except Exception as e:
            add(False, "Nap thu vien", "%s. Neu Python 64-bit thi DLL token cung phai 64-bit (va nguoc lai)." % e)
            return jsonify(steps=steps)
        try:
            slots = list(lib.get_slots(token_present=True))
            if not slots:
                add(False, "Token", "Khong thay token. Cam USB token roi thu lai.")
                return jsonify(steps=steps)
            add(True, "Token", "; ".join(s.get_token().label.strip() for s in slots))
            n = sum(1 for _ in iter_certs(lib))
            add(n > 0, "Chung thu", "Tim thay %d chung thu." % n if n else "Token khong co chung thu.")
        except Exception as e:
            add(False, "Doc token", str(e))
    return jsonify(steps=steps)


# ---------------------------------------------------------------- ky
def build_stamp_style():
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.text import TextBoxStyle
    from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory

    font_path = CFG.get("font_path")
    if not font_path or not os.path.exists(font_path):
        raise RuntimeError("Khong thay font %s (can font co dau tieng Viet, vi du Arial)." % font_path)
    font = GlyphAccumulatorFactory(font_path, font_size=9)
    lines = ["Ký bởi: %(signer)s", "Ngày ký: %(ts)s"]
    if True:
        lines.append("Lý do: %(reason)s")
        lines.append("Nơi ký: %(location)s")
    return TextStampStyle(
        stamp_text="\n".join(lines),
        text_box_style=TextBoxStyle(font=font, font_size=9),
        border_width=1,
        timestamp_format="%d/%m/%Y %H:%M:%S",
    )


@app.route("/api/sign", methods=["POST"])
def sign():
    f = request.files.get("pdf")
    if not f:
        return err("Chua co file PDF.")
    try:
        page = int(request.form["page"])
        box = tuple(float(v) for v in request.form["box"].split(","))
        if len(box) != 4:
            raise ValueError
    except Exception:
        return err("Vi tri khung ky khong hop le.")
    cert_id = request.form.get("cert_id", "")
    cert_label = request.form.get("cert_label", "")
    pin = request.form.get("pin", "")
    reason = request.form.get("reason", "").strip() or "Tôi đồng ý nội dung hợp đồng"
    location = request.form.get("location", "").strip() or "-"
    if not pin:
        return err("Chua nhap ma PIN.")

    pdf_bytes = f.read()
    with TOKEN_LOCK:
        try:
            import pkcs11
            from pkcs11 import exceptions as p11x
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            from pyhanko.sign import signers, fields
            from pyhanko.sign.pkcs11 import PKCS11Signer

            lib, _ = open_lib()
            target_slot = None
            for slot, _token, obj in iter_certs(lib):
                c = parse_cert(obj)
                if c["id"] == cert_id and c["label"] == cert_label:
                    target_slot = slot
                    break
            if target_slot is None:
                return err("Khong tim thay chung thu tren token. Bam 'Lam moi' roi thu lai.")

            token = target_slot.get_token()
            writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
            field_name = "Sig_%d" % int(time.time() * 1000)
            meta = signers.PdfSignatureMetadata(
                field_name=field_name, reason=reason, location=location, md_algorithm="sha256")

            timestamper = None
            if CFG.get("timestamp_url"):
                from pyhanko.sign.timestamps import HTTPTimeStamper
                timestamper = HTTPTimeStamper(CFG["timestamp_url"])

            kwargs = dict(use_raw_mechanism=bool(CFG.get("use_raw_mechanism")))
            if cert_id:
                kwargs.update(cert_id=bytes.fromhex(cert_id), key_id=bytes.fromhex(cert_id))
            else:
                kwargs.update(cert_label=cert_label)

            with token.open(user_pin=pin) as session:
                signer = PKCS11Signer(session, **kwargs)
                pdf_signer = signers.PdfSigner(
                    meta, signer=signer, timestamper=timestamper,
                    stamp_style=build_stamp_style(),
                    new_field_spec=fields.SigFieldSpec(
                        sig_field_name=field_name, on_page=page - 1, box=box))
                out = io.BytesIO()
                pdf_signer.sign_pdf(
                    writer, output=out,
                    appearance_text_params={"reason": reason, "location": location})
            out.seek(0)
            resp = make_response(out.read())
            resp.headers["Content-Type"] = "application/pdf"
            return resp
        except Exception as e:
            name = type(e).__name__
            if name in ("PinIncorrect", "PinInvalid", "PinLenRange"):
                return err("Mã PIN không đúng. Kiểm tra lại, tránh nhập sai nhiều lần vì token sẽ bị khóa.", 401)
            if name == "PinLocked":
                return err("Token đã bị khóa do nhập sai PIN quá số lần. Liên hệ nhà cung cấp chữ ký số để mở khóa.", 403)
            traceback.print_exc()
            return err("Ký thất bại: %s: %s" % (name, e), 500)


# ---------------------------------------------------------------- main
def main():
    url = CFG.get("open_url") or "http://127.0.0.1:%d" % PORT
    print("KySoPDF (Windows 7) dang chay tai %s" % url)
    print("Giu cua so nay mo trong luc ky. Dong cua so de tat chuong trinh.")
    if CFG.get("open_browser"):
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=PORT, threaded=False, use_reloader=False)


if __name__ == "__main__":
    main()
