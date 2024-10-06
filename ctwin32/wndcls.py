################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import lzma
import base64

import ctypes
from .wtypes import (
    string_buffer,
    HANDLE,
    HWND,
    LPARAM,
    POINT,
    PPOINT,
    PVOID,
    UINT,
    WORD,
    )
from . import (
    ref,
    kernel,
    user,
    gdi,
    BST_CHECKED,
    BST_UNCHECKED,
    BS_DEFPUSHBUTTON,
    COLOR_WINDOW,
    CS_DBLCLKS,
    CS_HREDRAW,
    CS_VREDRAW,
    CW_USEDEFAULT,
    DWLP_MSGRESULT,
    DS_MODALFRAME,
    DS_SETFONT,
    EM_SETPASSWORDCHAR,
    ES_AUTOHSCROLL,
    ES_LEFT,
    GWLP_HINSTANCE,
    GWL_EXSTYLE,
    GWL_STYLE,
    HIWORD,
    HORZRES,
    HORZSIZE,
    HWND_TOP,
    HWND_TOPMOST,
    IDCANCEL,
    IDC_ARROW,
    IDOK,
    LOWORD,
    SS_CENTER,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    SW_SHOW,
    SW_HIDE,
    WA_INACTIVE,
    WM_ACTIVATE,
    WM_COMMAND,
    WM_GETFONT,
    WM_INITDIALOG,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_NOTIFY,
    WS_BORDER,
    WS_CAPTION,
    WS_CHILD,
    WS_GROUP,
    WS_OVERLAPPEDWINDOW,
    WS_POPUP,
    WS_SYSMENU,
    WS_TABSTOP,
    WS_VISIBLE,
    )

################################################################################

class BaseWnd:

    def __init__(self, hwnd=None):
        self.hwnd = hwnd

    def def_win_proc(self, msg, wp, lp):
        return user.DefWindowProc(self.hwnd, msg, wp, lp)

    def is_window(self):
        return bool(user.IsWindow(self.hwnd))

    def get_dlg_item(self, id):
        return BaseWnd(user.GetDlgItem(self.hwnd, id))

    def send_msg(self, msg, wp, lp):
        return user.SendMessage(self.hwnd, msg, wp, lp)

    def post_msg(self, msg, wp, lp):
        user.PostMessage(self.hwnd, msg, wp, lp)

    def send_dlg_item_msg(self, id, msg, wp, lp):
        return user.SendDlgItemMessage(self.hwnd, id, msg, wp, lp)

    def set_dlg_item_text(self, id, txt):
        user.SetDlgItemText(self.hwnd, id, txt)

    def get_dlg_item_text(self, id):
        return user.GetDlgItemText(self.hwnd, id)

    def send_notify(self, nmhdr):
        return user.SendMessage(
            self.hwnd,
            WM_NOTIFY,
            nmhdr.idFrom,
            LPARAM(ctypes.cast(ref(nmhdr), PVOID).value)
            )

    def destroy(self):
        if self.is_window():
            user.DestroyWindow(self.hwnd)
            self.hwnd = None

    def show(self, how=SW_SHOW):
        user.ShowWindow(self.hwnd, how)

    def hide(self):
        user.ShowWindow(self.hwnd, SW_HIDE)

    def enable(self, enabled=True):
        user.EnableWindow(self.hwnd, enabled)

    def disable(self):
        user.EnableWindow(self.hwnd, False)

    def activate(self):
        user.SetActiveWindow(self.hwnd)

    def set_foreground(self):
        user.SetForegroundWindow(self.hwnd)

    def set_focus(self):
        return BaseWnd(user.SetFocus(self.hwnd))

    def invalidate_rect(self, rc=None, erase=False):
        user.InvalidateRect(self.hwnd, rc, erase)

    def update(self):
        user.UpdateWindow(self.hwnd)

    def get_parent(self):
        return BaseWnd(user.GetParent(self.hwnd))

    def get_menu(self):
        return user.GetMenu(self.hwnd)

    def move(self, rc, repaint=True):
        user.MoveWindow(
            self.hwnd,
            rc.left,
            rc.top,
            rc.width(),
            rc.height(),
            repaint
            )

    def set_pos(self, wnd_ins_after, x, y, cx, cy, flags):
        user.SetWindowPos(
            self.hwnd,
            None if wnd_ins_after is None else wnd_ins_after.hwnd,
            x,
            y,
            cx,
            cy,
            flags
            )

    def center(self, center_on=None):
        user.center_wnd(self.hwnd, center_on.hwnd if center_on else None)

    def set_topmost(self):
        self.set_pos(
            BaseWnd(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
            )

    def set_non_topmost(self):
        self.set_pos(
            BaseWnd(HWND_TOP),
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
            )

    def bring_to_top(self):
        user.BringWindowToTop(self.hwnd)

    def map_window_point(self, to_bwnd, pt):
        user.MapWindowPoints(self.hwnd, to_bwnd.hwnd, ref(pt), 1)
        return pt

    def map_window_rect(self, to_bwnd, rc):
        ppt = ctypes.cast(ref(rc), PPOINT)
        user.MapWindowPoints(self.hwnd, to_bwnd.hwnd, ppt, 2)
        return rc

    def lp_pt_to_parent(self, lp):
        pt = POINT.from_lparam(lp)
        user.MapWindowPoints(self.hwnd, user.GetParent(self.hwnd), ref(pt), 1)
        return pt.as_lparam()

    def client_to_screen(self, pt_or_rc):
        meth = (
            self.map_window_point if isinstance(pt_or_rc, POINT)
            else self.map_window_rect
            )
        return meth(BaseWnd(), pt_or_rc)

    def window_rect(self):
        return user.GetWindowRect(self.hwnd)

    def client_rect(self):
        return user.GetClientRect(self.hwnd)

    def adjust_window_rect(self, rc):
        frame = user.AdjustWindowRectEx(
            rc,
            self.get_style(),
            bool(self.get_menu()),
            self.get_exstyle()
            )
        self.set_pos(None, 0, 0, frame.width, frame.height, SWP_NOMOVE)

    def window_rect_as_client(self):
        rc = self.window_rect()
        ppt = ctypes.cast(ref(rc), PPOINT)
        user.MapWindowPoints(None, self.hwnd, ppt, 2)
        return rc

    def window_rect_as_other_client(self, other):
        rc = self.window_rect()
        ppt = ctypes.cast(ref(rc), PPOINT)
        user.MapWindowPoints(None, other.hwnd, ppt, 2)
        return rc

    def get_cursor_pos(self):
        pt = user.GetCursorPos()
        user.MapWindowPoints(None, self.hwnd, ref(pt), 1)
        return pt

    def get_nc_cursor_pos(self):
        pt = user.GetCursorPos()
        rc = self.window_rect()
        pt.x -= rc.left
        pt.y -= rc.top
        return pt

    def cursor_over_thread_wnd(self):
        pt = user.GetCursorPos()
        tid, _ = user.GetWindowThreadProcessId(user.WindowFromPoint(pt))
        return (tid == kernel.GetCurrentThreadId())

    def get_dc(self):
        return user.GetDC(self.hwnd)

    def release_dc(self, hdc):
        user.ReleaseDC(self.hwnd, hdc)

    def get_dpi_scale_100(self):
        hdc = self.get_dc()
        try:
            hres = gdi.GetDeviceCaps(hdc, HORZRES)
            hsize = gdi.GetDeviceCaps(hdc, HORZSIZE)
            dpi_100 = (hres * 2540 + hsize // 2) // hsize
            return (dpi_100 + 48) // 96
        finally:
            self.release_dc(hdc)

    def get_style(self):
        return user.GetWindowLong(self.hwnd, GWL_STYLE)

    def get_exstyle(self):
        return user.GetWindowLong(self.hwnd, GWL_EXSTYLE)

    def modify_style(self, remove, add, flags=0, idx=GWL_STYLE):
        style = user.GetWindowLong(self.hwnd, idx)
        new_style = (style & ~remove) | add
        if new_style != style:
            user.SetWindowLong(self.hwnd, idx, new_style)
            if flags:
                flags |= SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER
                self.set_pos(None, 0, 0, 0, 0, flags)

    def modify_exstyle(self, remove, add, flags=0):
        self.modify_style(remove, add, flags, GWL_EXSTYLE)

    def hinstance(self):
        return HANDLE(user.GetWindowLongPtr(self.hwnd, GWLP_HINSTANCE))

    def set_timer(self, id, period):
        user.SetTimer(self.hwnd, id, period)

    def kill_timer(self, id):
        user.KillTimer(self.hwnd, id)

    def set_text(self, txt):
        user.SetWindowText(self.hwnd, txt)

    def get_text(self):
        return user.GetWindowText(self.hwnd)

    def get_font(self):
        return HANDLE(self.send_msg(WM_GETFONT, 0, 0))

    def check_dlg_button(self, id, checked):
        user.CheckDlgButton(
            self.hwnd,
            id,
            BST_CHECKED if checked else BST_UNCHECKED
            )

    def is_dlg_button_checked(self, id):
        return (user.IsDlgButtonChecked(self.hwnd, id) == BST_CHECKED)

    def check_radio_button(self, first, last, check):
        user.CheckRadioButton(self.hwnd, first, last, check)

    def begin_paint(self):
        return user.BeginPaint(self.hwnd)

    def end_paint(self, ps):
        user.EndPaint(self.hwnd, ps)

    def set_prop(self, name, data):
        user.SetProp(self.hwnd, name, data)

    def get_prop(self, name):
        return user.GetProp(self.hwnd, name)

    def get_prop_def(self, name, default=None):
        return user.get_prop_def(self.hwnd, name, default)

    def del_prop(self, name):
        return user.RemoveProp(self.hwnd, name)

################################################################################
################################################################################
################################################################################

class WndCreateParams:
    def __init__(self, name="", icon=0, style=WS_OVERLAPPEDWINDOW):
        self.cls = user.WNDCLASS()
        self.cls.hbrBackground = COLOR_WINDOW + 1
        self.cls.hInstance = kernel.GetModuleHandle(None)
        self.cls.hCursor = user.LoadCursor(None, IDC_ARROW)
        self.cls.hIcon = icon
        self.cls.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS
        self.wnd_style = style
        self.ex_style = 0
        self.left = self.top = self.width = self.height = CW_USEDEFAULT
        self.menu = self.parent = None
        self.name = name

################################################################################

_PROP_SELF = kernel.global_add_atom("ctwin32:SimpleWnd:self")

class SimpleWnd(BaseWnd):

    def __init__(self, wc_params: WndCreateParams = None):
        self.hwnd = None
        self.parent = None
        if wc_params is not None:
            self.create(wc_params)

    ############################################################################

    def parent_hwnd(self):
        return self.parent.hwnd if self.parent else None

    ############################################################################

    @user.WNDPROC
    @staticmethod
    def _wnd_proc_(hwnd, msg, wp, lp):
        # Since this is a python callback that ctypes calls when requested
        # by foreign C code, ctypes has no way of propagating any exception
        # back to the python interpreter - those would simply be ignored.
        # Therefore any exception has to terminate the process.
        with kernel.terminate_on_exception():
            if msg != WM_NCCREATE:
                if self_prop := user.get_prop_def(hwnd, _PROP_SELF):
                    self = ctypes.cast(self_prop, ctypes.py_object).value
                    res = self.on_message(msg, wp, lp)
                    if msg == WM_NCDESTROY:
                        self.del_prop(_PROP_SELF)
                        self.hwnd = None
                    return res

                # Some kind of messages may arrive before WM_NCCREATE
                # (e.g. WM_GETMINMAXINFO), i.e. still self_prop == None.
                return user.DefWindowProc(hwnd, msg, wp, lp)

            cparam = user.CREATESTRUCT.from_address(lp).lpCreateParams
            self = ctypes.cast(cparam, ctypes.py_object).value
            if isinstance(self, SimpleWnd):
                self.hwnd = hwnd
                self.set_prop(_PROP_SELF, cparam)
                return self.on_message(msg, wp, lp)
            raise TypeError("not derived from SimpleWnd")

    ############################################################################

    def create(self, wcp):
        if self.is_window():
            raise RecursionError("can only be created once")
        self.parent = wcp.parent
        wcp.cls.lpfnWndProc = self._wnd_proc_

        if wcp.cls.lpszClassName is None:
            # calc hash over wcp.cls and cast it to unsigned
            h = hash(bytes(wcp.cls)) & (2 ** sys.hash_info.width - 1)
            wcp.cls.lpszClassName = f"ctwin32:{h:x}"

        try:
            user.GetClassInfo(wcp.cls.hInstance, wcp.cls.lpszClassName)
        except OSError:
            user.RegisterClass(wcp.cls)

        user.CreateWindowEx(
            wcp.ex_style,
            wcp.cls.lpszClassName,
            wcp.name,
            wcp.wnd_style,
            wcp.left,
            wcp.top,
            wcp.width,
            wcp.height,
            wcp.parent,
            wcp.menu,
            wcp.cls.hInstance,
            id(self)
            )

    ############################################################################

    def on_message(self, msg, wp, lp):
        raise NotImplementedError("must be implemented in derived class")

    ############################################################################

    def __del__(self):
        if self.is_window():
            self.destroy()

################################################################################

def to_lzb85(raw_data):
    return base64.b85encode(lzma.compress(raw_data))

################################################################################

def from_lzb85(lzb85_data):
    return lzma.decompress(base64.b85decode(lzb85_data))

################################################################################

def load_ico_lz_b85(lz_b85_data):
    return user.CreateIconFromResourceEx(from_lzb85(lz_b85_data))

################################################################################

_py_icon = (
    b"{Wp48S^xk9=GL@E0stWa761SMbT8$j;1H(;>RkX705Aj)f+J6yP9T}Bko})j#+i7N>;e(Cc8"
    b"*b~t=p!4Q*Y-|8I`wx%g@F}t$1qY3`ER*6QY*}qNii+qAYq`NROBYh+Ot_RpNEGPRoAI1^Td"
    b"&(&<AnDap)j_o`+IK<rpFw3)<etl<IYLkGU|B2d7e`60A9qtCtFsg1{>=)qA*sCV&QUE12Nq"
    b"qR_6W0oGLTfny)d!CWv4njsF>CeO1THX!>_^ENrpO&Oy0;%fq$|!F3nno<dnv3(2y{c&itUa"
    b"1iK56!K;Z`9i*&0yl8zC$m9Tv+nv1#?r;S#KU<`4!FpMXj?Ht_jotwz*o?L-cp`Gc?6%uw_6"
    b"t-iWwadkQ7p<wFOI{#$S>sEa%fQbn&d5~&Tf->4?!WxGsv#=5n_b6v8kR;1Cxo}y}5chHkKd"
    b"+8<F2RVe^G^ZEH+XgIa*gbPH{u*_zX);IzvXAhgqBMc`{q6a%PeKwiU|3SKU_TZo;yWN+Jy5"
    b"{H{pQ+Q)RoAL)HBGYX-&-tgz0xCGDfYU0rZ3x-h+7onOS%J|hx^_kxhEy4c&JL<s`(xMxnMY"
    b"3?)MsDJGWRx;uosq;9nuFDfkJz-rEujXPpx0UITtH-mffmG<;y@p5W9+R*F!}6-#vKH-+lyX"
    b";J+#?QvOB7uPy4C53q`2Bt%8BHejw~~yQp1p{IKP_zJ3!Oq7|+)Ds@pyQ_64-$*ww>zN_2t5"
    b"o6k+215Gr)oYa5_P2;!g`oDgxp@9XFqjZ0x0m6TN5EZEvT?mtyP@QR*?VdVxiqkI%LqCL_04"
    b"8HcMK?Ej3afNs@Qs2L9gev&tW=$BmQbP*Gs+reQAWKocl|u*?5E^;`<qa9m|E&NKq1GAK$lC"
    b"4gp*7+h$GLJ;1nx8-No(Y%o*@?nBP8sE3D2`G3|+d)3Ul+wliQ~7A9gsR8N!>nL@g}ZSFIE<"
    b"3m(pl;5Ur1C9Mqcuyh-kf^e??xt{`a4E{mmds6mf6NUP&GKgkxYRM(g}FU5>lb>wTQ(m8dsL"
    b"{N-YuOa>4c3fm+n`!MpQ_(c6FmIq5-rI5_=(FhR{10ek%v;Pb!Y9)b1iKktnF@^w8;oP<S57"
    b"B-quZtTE=3L>_6TdPcc0A*;>4w-Y=gs%Z@-EDdv0g4m8a#V|5<Zt;?(@wYrVb-Mk1Zdw%Y09"
    b"Gn=e1&7;wA~N&ryFEU*V)J&^KvQY@Ak>Zm{0ooZsRK7?-#1(gu$iVqGdslP=0S|Q3<Fa-xec"
    b"8uu5r%nQ4UlsMx^Vni(7Bskl7aQdNJe>Db2}fWQ}$geIyG@D7n&OyNG7>c!_70Cy>lzy?L6p"
    b"<=%0-^CQkVI#_teeId#xO_L^xsUL?ycSIzlppqI74YA6(Zt6g{fFa6gQ(#f&Xs(UOr7@lz7L"
    b"Xc%_<xA_oa^vO}LkvmhHHq%Qe_z3^am;#oZ~$FtL3o@Cl{K^hF6+CUh+JE8-<96BRbQ2sw+0"
    b"07hXrCaq6ZRIn6iVjyQ^ufxm4gbLmXnMgIjh?7(|D&?Nlb2S%9rK@)Jz_irCdm`I{$-zZLXJ"
    b"v!RG$;h}KR@@r7eX*74~#4FYiyZBtxv8w`%IDomf2+mQ=p-v-~~BnB4ky$7MTefMN~%ZLb%`"
    b"9HAuZy>YC5wbuq}fsUv>XN>?<(K|l9W_i0*$<>pocq&1w+=2XX=ZTZ!b+9?|3)6=`R%F!}Z&"
    b"a3Qm#HB{fW|T^Vk!~MbAjB%uoKE2KB?<{2C4_7P^XpCPOvLvb*=`u!@U??9&!FwtogjvKchT"
    b"JYXIjeMr`}Q^G8vJ%n;<f;*!&FZ!Ihx~1V$NR`5Y3LJT5Gs{MWKOM$(1PgZT`{b##@>Y~@{s"
    b")vnA~VaZp}VEy{WN=0EzUX~N5K4PI_3hVd(<@S@?%#NnfV#o&CTj&LSlM;dAJ}n;7UKjmt%e"
    b"cG-MV+#m^)RYoItH4F4SpRv>o$*ci&39VZ{Gn)82#qhvYI77MY6k>v2iQs00000F``J)J91k"
    b"700D*!s38CVB-0#!vBYQl0ssI200dcD"
    )

def load_py_ico():
    return load_ico_lz_b85(_py_icon)

################################################################################

_ctwin32_icon = (
    b"{Wp48S^xk9=GL@E0stWa761SMbT8$j;0UJ#&0PQ#05Aj)f+J6yaHvHu1q>Gs(yZ)`rT4VqYn"
    b"%B-HIH~>jeV{SNI_{JHVRTYsiKzK7CwQ=tJ2Ks!~srhl-I*p0o!hI-fpo^97Xi*4Q!Dd3X}v"
    b"$8WKulmA{F!7oZCs)IAY;ZLMh6_No@b0ca=PkNzVlN3cC!ob60RrU0=4ndqroAy}qIF?$;ZH"
    b"Ufdr4QqNydBJoi**2(b>LJtsq1--PQVunbK*nFuD0^<0YG0-)S3tS_@5y)&cQ=s^k)-n~=oM"
    b"02WzYUu?pZecGjm&)ry+Orfv<jRMfx!kc1P+ahYuS(p%J>Y|E(NvE5ZQb(61)+uYPYcZKA?4"
    b"y3*?c3~|o@e>T)A&e2>Qsiwrg(x})20YiS)c@q~frD|ufg|rFed$7w!;pG&;vB0orztE80g1"
    b"5I$1~{%oA8kJqG8F5WFuF%de0KZlqk)<^C2K?eE3mj3mf16t&%ma@|F%17nc2|)O8_#Lldac"
    b"FKC#?m7Ga6mIU+oCQ4>>QHY^>Au-AQr)+1y^BmO-flIkHJsV)N);I;ebT<`hX9)46w<Rg3FL"
    b"i)nM%7pg~SO#qz-ze-1-*zMpUl#X<!?Q_$_PfG77v&?(kBe4H7IG?zCE?~%aW3h~O~Nk#)1H"
    b"v=0R1#>@CNEYYT5RzSq>D#w>P>#BfdIYc)Z?l^6ml~-ykX8X8NnIqKq+G;v$hN(Y<Jt)r?c9"
    b">GCHY0zJilG#Dgj6g&_Ar1vUBMuh7e1c=)&+mJs_S(AEH(w+z@wOPz`09ec$bD^<B20sPmtQ"
    b";9O8ejb}|4A@5yHoQ|la1UXI=fK{SBk8E0dNDC-7yw%?a9h+@fRDw!w6q>w{eR6p%f9?J2ey"
    b"sbWHE%E5LjOC=}=%xLInY)d36&`<eV73u+U8SBisPCILL$*_AbshRHS~A(Eo9HFi__M)NO{L"
    b"k}hiLF?7EhWwHZo$Xt984N&;?2^{2k^@GcRUbM$+nhqIJ0$;#L=XESY=_B_hRlCH6Hx-@ItE"
    b"@4C^*r-Z*y%%>?H81t0$s$1c97#vHl%HhMw%^^5Tid??!_#@o>WP7mN#K1i21pownz?8>#_R"
    b"67v0mi1&j!iRKMdj-fwjC}mJ4deM2@pDkT)?qtiS1a~80#D^R~9XM3@7QZL?zs-ZA-pCJo6{"
    b"R>GbdV}c`%kbaf1&ZpLT&u%w>OgdQZ*~7)q(fpFA=qdeAt|9=O5NX(*%bl8iYPJ(FJbra1Lc"
    b"1<m23X?h%S;!h}bzIodaWjLg}aLqJ_oc`_kb`^egLfTdLSI6#rFaK)MtiwsG%!qr%(+$M7=i"
    b"FsygaUfDcG1`f1)_y!(vw(U!A(ly-<MbTl&@rjG$BKX<x{({u@XJ*QsEUvq@f(bmc6v=U8!5"
    b"}p{K5@GE7Jm9Z!Bv3CFo#1ZHV7*nTNaA10bQO+6x22LetMJ2b#}!7h6#~GL*UD=`~w_>msdT"
    b"YdUl6{}zNFtK;1wkl9@$K|*;m;I}jOF`7rfqE9`8A2}5MAYGOm&Bd@13Bgk?!sLhcJ65PFvq"
    b"EK-oczoVl#{I->+Rapc9fQ>LT)>~&`%W3cz@D3$X)<L+qpZSQ4LslJyc~^rDkdX00000gHzk"
    b"KXFSSV00HR<s1X1FO9VA)vBYQl0ssI200dcD"
    )

def load_ctwin32_ico():
    return load_ico_lz_b85(_ctwin32_icon)

################################################################################

class BaseDlg(BaseWnd):

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent

    ############################################################################

    def parent_hwnd(self):
        return self.parent.hwnd if self.parent else None

    ############################################################################

    @user.DLGPROC
    @staticmethod
    def _dlg_proc_(hwnd, msg, wp, lp):
        # Since this is a python callback that ctypes calls when requested
        # by foreign C code, ctypes has no way of propagating any exception
        # back to the python interpreter - those would simply be ignored.
        # Therefore any exception has to terminate the process.
        with kernel.terminate_on_exception():
            if msg != WM_INITDIALOG:
                if self_prop := user.get_prop_def(hwnd, _PROP_SELF):
                    self = ctypes.cast(self_prop, ctypes.py_object).value
                    if msg == WM_COMMAND:
                        return self.on_command(
                            LOWORD(wp),
                            HIWORD(wp),
                            HWND(lp)
                            )
                    elif msg == WM_NOTIFY:
                        return self.on_notify(
                            UINT(wp).value,
                            ctypes.cast(lp, user.PNMHDR)
                            )
                    else:
                        if msg == WM_ACTIVATE and self.parent:
                            hdr = user.NMHDR(
                                hwnd,
                                user.GetDlgCtrlID(hwnd),
                                user.MSDN_ACTIVATE
                                )
                            ma = user.NM_MSD_ACTIVATE(hdr, wp != WA_INACTIVE)
                            self.parent.send_notify(ref(ma.hdr))
                        res = self.on_message(msg, wp, lp)
                        if (msg == WM_NCDESTROY):
                            self.del_prop(_PROP_SELF)
                            self.hwnd = None
                        return res
                else:
                    return False
            else:
                self = ctypes.cast(lp, ctypes.py_object).value
                if isinstance(self, BaseDlg):
                    self.hwnd = hwnd
                    self.set_prop(_PROP_SELF, lp)
                    return self.on_init_dialog()
                raise TypeError("not derived from BaseDlg")

    ############################################################################

    def create_modeless(self, template):
        return user.CreateDialogIndirectParam(
            template,
            self.parent,
            self._dlg_proc_,
            id(self)
            )

    ############################################################################

    def do_modal(self, template):
        return user.DialogBoxIndirectParam(
            template,
            self.parent,
            self._dlg_proc_,
            id(self)
            )

    ############################################################################

    def on_message(self, msg, wp, lp):
        return False

    def on_init_dialog(self):
        return True

    def on_command(self, cmd_id, notification, ctrl):
        user.EndDialog(self.hwnd, IDCANCEL)
        return True

    def on_notify(self, ctrl_id, pnmhdr):
        return False

    def __del__(self):
        self.destroy()

    def get_item(self, id):
        return self.get_dlg_item(id)

    def set_item_text(self, id, txt):
        return self.set_dlg_item_text(id, txt)

    def get_item_text(self, id):
        return self.get_dlg_item_text(id)

    def is_button_checked(self, id):
        return self.is_dlg_button_checked(id)

    def check_button(self, id, check):
        self.check_dlg_button(id, check)

    def send_destroy_request(self):
        if self.parent:
            md = user.NM_MSD_DESTROY(
                self.hwnd,
                user.GetDlgCtrlID(self.hwnd),
                user.MSDN_DESTROY
                )
            self.parent.send_notify(ref(md))
        else:
            self.destroy()

    def set_msg_result(self, result):
        user.SetWindowLongPtr(self.hwnd, DWLP_MSGRESULT, result)

################################################################################

_std_classes = {
    "button":    b"\xff\xff" + bytes(WORD(0x80)),
    "edit":      b"\xff\xff" + bytes(WORD(0x81)),
    "static":    b"\xff\xff" + bytes(WORD(0x82)),
    "listbox":   b"\xff\xff" + bytes(WORD(0x83)),
    "scrollbar": b"\xff\xff" + bytes(WORD(0x84)),
    "combobox":  b"\xff\xff" + bytes(WORD(0x85)),
    }

################################################################################

def dlg_item_template(
        style,
        x,
        y,
        cx,
        cy,
        id,
        cls,
        title,
        cdata=None
        ):
    style |= WS_VISIBLE | WS_CHILD
    # bytes = template + class + title + creation data
    cls = (
        _std_classes.get(cls.lower(), None) or
        bytes(string_buffer(cls))
        )
    cdata = (
        bytes(WORD(0)) if cdata is None
        else bytes(WORD(len(cdata))) + cdata
        )
    bts = (
        bytes(user.DLGITEMTEMPLATE(style, 0, x, y, cx, cy, id)) +
        cls +
        bytes(string_buffer(title)) +
        cdata
        )
    # align to DWORD for the following items
    bts += (-len(bts) % 4) * b"\0"
    assert len(bts) % 4 == 0
    return bts

################################################################################

def dlg_template(
        items,
        style,
        x,
        y,
        cx,
        cy,
        title,
        typeface,
        pointsize=8,
        ):
    # bytes = template + menu + class + title + pointsize + typeface + items
    style |= DS_SETFONT  # always set font
    tmpl = user.DLGTEMPLATE(style, 0, len(items), x, y, cx, cy)
    bts = b"".join((
        bytes(tmpl),
        bytes(WORD(0)),     # no menu
        bytes(WORD(0)),     # default class
        bytes(string_buffer(title)),
        bytes(WORD(pointsize)),
        bytes(string_buffer(typeface))
        ))
    return b"".join((
        bts,
        (-len(bts) % 4) * b"\0",  # align to DWORD for the following items
        *(dlg_item_template(*item) for item in items)
        ))

################################################################################

class InputDlg(BaseDlg):

    QUESTION_ID = 100
    ANSWER_ID   = 101
    ED_STYLE = ES_AUTOHSCROLL | ES_LEFT | WS_BORDER | WS_TABSTOP
    DLG_ITEMS = (
        (SS_CENTER | WS_GROUP, 7, 7, 201, 18, QUESTION_ID, "static", ""),
        (ED_STYLE, 7, 31, 201, 13, ANSWER_ID, "edit", ""),
        (BS_DEFPUSHBUTTON | WS_TABSTOP, 104, 51, 50, 14, IDOK, "button", "OK"),
        (WS_TABSTOP, 158, 51, 50, 14, IDCANCEL, "button", "Cancel"),
        )

    ############################################################################

    def __init__(self, fontsize=8, parent=None):
        self.fontsize = fontsize
        self.question = None
        self.answer = None
        self.password = False
        super().__init__(parent)

    ############################################################################

    def on_init_dialog(self):
        if self.password:
            # black circle -> U+25cf -> 9679
            self.get_item(self.ANSWER_ID).send_msg(EM_SETPASSWORDCHAR, 9679, 0)

        if self.question is not None:
            self.set_item_text(self.QUESTION_ID, self.question)

        self.center(self.parent)
        return True

    ############################################################################

    def on_command(self, cmd_id, notification, ctrl):
        if cmd_id in (IDOK, IDCANCEL):
            if cmd_id == IDOK:
                self.answer = self.get_item_text(self.ANSWER_ID)
            user.EndDialog(self.hwnd, cmd_id)
        return True

    ############################################################################

    def ask(self, question, caption="", password=False):
        self.question = question
        self.password = password
        template = dlg_template(
            self.DLG_ITEMS,
            DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU,
            0,
            0,
            215,
            72,
            caption,
            "MS Shell Dlg",
            (self.fontsize * self.get_dpi_scale_100() + 50) // 100
            )

        return self.answer if self.do_modal(template) == IDOK else None

################################################################################
