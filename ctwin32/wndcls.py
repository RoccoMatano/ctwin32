################################################################################
#
# Copyright 2021-2022 Rocco Matano
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
################################################################################

import sys
import traceback
import lzma
import base64

from .wtypes import *
from . import (
    ref,
    fun_fact,
    kernel,
    user,
    gdi,
    WM_NOTIFY,
    SW_SHOW,
    HWND_TOP,
    HWND_TOPMOST,
    SWP_NOSIZE,
    SWP_NOMOVE,
    SWP_NOACTIVATE,
    HORZRES,
    HORZSIZE,
    GWL_STYLE,
    GWL_EXSTYLE,
    GWLP_HINSTANCE,
    BST_CHECKED,
    BST_UNCHECKED,
    COLOR_WINDOW,
    IDC_ARROW,
    CW_USEDEFAULT,
    WS_OVERLAPPEDWINDOW,
    CS_HREDRAW,
    CS_VREDRAW,
    CS_DBLCLKS,
    WM_NCCREATE,
    GWLP_USERDATA,
    WM_NCDESTROY,
    SW_SHOW,
    MB_OK,
    MB_ICONERROR,
    )

################################################################################

class NMHDR(ctypes.Structure):
    _fields_ = (
        ("hwndFrom", HWND),
        ("idFrom", UINT_PTR),
        ("code", UINT),
        )

PNMHDR = POINTER(NMHDR)

################################################################################

class BaseWnd:

    def __init__(self, hwnd=None):
        self.hwnd = hwnd

    def def_win_proc(self, msg, wp, lp):
        return user.DefWindowProc(self.hwnd, msg, wp, lp)

    def is_window(self):
        return bool(user.IsWindow(self.hwnd))

    def get_dlg_item(self, id):
        return self.__class__(user.GetDlgItem(self.hwnd, id))

    def send_msg(self, msg, wp, lp):
        return user.SendMessage(self.hwnd, msg, wp, lp)

    def post_msg(self, msg, wp, lp):
        user.PostMessage(self.hwnd, msg, wp, lp)

    def send_dlg_item_msg(self, id , msg, wp, lp):
        return user.SendDlgItemMessage(self.hwnd, id, msg, wp, lp)

    def set_dlg_item_text(self, id , txt):
        user.SetDlgItemText(self.hwnd, id, txt)

    def send_notify(self, nmhdr):
        return user.SendMessage(
            self.hwnd,
            WM_NOTIFY,
            nmhdr.idFrom,
            LPARAM(ctypes.cast(ref(nmhdr), PVOID).value)
            )

    def destroy(self):
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
        return self.__class__(user.SetFocus(self.hwnd))

    def invalidate_rect(self, rc=None, erase=False):
        user.InvalidateRect(self.hwnd, rc, erase)

    def update(self):
        user.UpdateWindow(self.hwnd)

    def get_parent(self):
        return self.__class__(user.GetParent(self.hwnd))

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

    def set_topmost(self):
        self.set_pos(
            self.__class__(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
            )

    def set_non_topmost(self):
        self.set_pos(
            self.__class__(HWND_TOP),
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
        return meth(self.__class__(), pt_or_rc)

    def window_rect(self):
        return user.GetWindowRect(self.hwnd)

    def client_rect(self):
        return user.GetClientRect(self.hwnd)

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
        return pt;

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
                flags |= SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER;
                self.SetPos(None, 0, 0, 0, 0, flags);

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

    def check_dlg_button(id, checked):
        user.CheckDlgButton(
            self.hwnd,
            id,
            BST_CHECKED if checked else BST_UNCHECKED
            )

    def is_dlg_button_checked(self, id):
        return (user.IsDlgButtonChecked(self.hwnd, id) == BST_CHECKED)

    def begin_paint(self):
        return user.BeginPaint(self.hwnd)

    def end_paint(self, ps):
        user.EndPaint(self.hwnd, ps)

    def set_prop(self, name, data):
        user.SetProp(self.hwnd, name, data)

    def get_prop(self, name, data):
        return user.GetProp(self.hwnd, name)

    def get_prop_def(self, name, data, default=None):
        return user.get_prop_def(self.hwnd, name, default)

    def del_prop(self, name):
        return user.RemoveProp(self.hwnd, name)

################################################################################
################################################################################
################################################################################

class WndCreateParams:
    def __init__(self):
        self.cls = user.WNDCLASS()
        self.cls.hbrBackground = COLOR_WINDOW + 1
        self.cls.hInstance = kernel.GetModuleHandle(None)
        self.cls.hCursor = user.LoadCursor(None, IDC_ARROW)
        self.cls.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS
        self.wnd_style = WS_OVERLAPPEDWINDOW
        self.ex_style = 0
        self.left = self.top = self.width = self.height = CW_USEDEFAULT
        self.menu = self.parent = None
        self.name = ""

################################################################################

_PROP_SELF = kernel.global_add_atom("ctwin32:SimpleWnd:self")

class SimpleWnd(BaseWnd):

    def __init__(self, wc_params: WndCreateParams = None):
        self.hwnd = None
        self.parent = None
        if wc_params is not None:
            self.create(wc_params)

    ############################################################################

    @user.WNDPROC
    @staticmethod
    def _wnd_proc_(hwnd, msg, wp, lp):
        # Since this is a python callback that ctypes calls when requested
        # by foreign C code, ctypes has no way of propagating any exception
        # that might get raised back to the python interpreter - that exception
        # would simply be ignored. Therefore we have to catch all unhandled
        # exceptions here. In such a case we try to inform the user and
        # terminate the program.
        try:
            if msg != WM_NCCREATE:
                self_prop = user.get_prop_def(hwnd, _PROP_SELF)
                if self_prop:
                    self = ctypes.cast(self_prop, ctypes.py_object).value
                    res = self.on_message(msg, wp, lp)
                    if msg == WM_NCDESTROY:
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
            else:
                raise TypeError("not derived from SimpleWnd")
        except BaseException:
            err_info = traceback.format_exc()
            if sys.stderr is None or not hasattr(sys.stderr, 'mode'):
                user.txt_to_clip(err_info)
                err_info += '\nThe above text has been copied to the clipboard.'
                user.MessageBox(
                    None,
                    err_info,
                    "Terminating program",
                    MB_OK | MB_ICONERROR
                    )
            else:
                sys.stderr.write(err_info)

            # Calling sys.exit() here won't help, since it depends on exception
            # propagation. We could hope that this thread is pumping messages
            # while watching for WM_QUIT messages and post such a message.
            # Since this possibility seems too vague, we play it safe
            # and call:
            kernel.ExitProcess(1)

    ############################################################################

    def create(self, wcp):
        if self.is_window():
            raise RecursionError("can only be created once")
        self.parent = wcp.parent
        wcp.cls.lpfnWndProc = self._wnd_proc_

        if wcp.cls.lpszClassName is None:
            # calc hash over wcp.cls and in case it is negative convert it
            # to its two's complement.
            h = hash(bytes(wcp.cls))
            h = h & (2 ** (h.bit_length() + 1) - 1)
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
            # PVOID (or more precisely ctypes.c_void_p) has a flaw: neither can
            # PVOID.from_param() process a py_object, nor does ctypes.cast()
            # allow to convert a py_object to a PVOID (
            # ctypes.cast(ctypes.py_object(self), PVOID) fails).
            # Therefore we need this odd way of converting a python object
            # pointer to PVOID.
            PVOID.from_buffer(ctypes.py_object(self))
            )

    ############################################################################

    def on_message(self, msg, wp, lp):
        raise NotImplementedError("must be implemented in derived class")

    ############################################################################

    def __del__(self):
        if self.is_window():
            self.destroy()

################################################################################

def load_ico_lzma_b85(lzma_b85_data):
    data = lzma.decompress(base64.b85decode(lzma_b85_data))
    return user.CreateIconFromResourceEx(data)

################################################################################

_py_icon = (
    b'{Wp48S^xk9=GL@E0stWa761SMbT8$j;1H(;>RkX705Aj)f+J6yP9T}Bko})j#+i7N>;e(Cc8'
    b'*b~t=p!4Q*Y-|8I`wx%g@F}t$1qY3`ER*6QY*}qNii+qAYq`NROBYh+Ot_RpNEGPRoAI1^Td'
    b'&(&<AnDap)j_o`+IK<rpFw3)<etl<IYLkGU|B2d7e`60A9qtCtFsg1{>=)qA*sCV&QUE12Nq'
    b'qR_6W0oGLTfny)d!CWv4njsF>CeO1THX!>_^ENrpO&Oy0;%fq$|!F3nno<dnv3(2y{c&itUa'
    b'1iK56!K;Z`9i*&0yl8zC$m9Tv+nv1#?r;S#KU<`4!FpMXj?Ht_jotwz*o?L-cp`Gc?6%uw_6'
    b't-iWwadkQ7p<wFOI{#$S>sEa%fQbn&d5~&Tf->4?!WxGsv#=5n_b6v8kR;1Cxo}y}5chHkKd'
    b'+8<F2RVe^G^ZEH+XgIa*gbPH{u*_zX);IzvXAhgqBMc`{q6a%PeKwiU|3SKU_TZo;yWN+Jy5'
    b'{H{pQ+Q)RoAL)HBGYX-&-tgz0xCGDfYU0rZ3x-h+7onOS%J|hx^_kxhEy4c&JL<s`(xMxnMY'
    b'3?)MsDJGWRx;uosq;9nuFDfkJz-rEujXPpx0UITtH-mffmG<;y@p5W9+R*F!}6-#vKH-+lyX'
    b';J+#?QvOB7uPy4C53q`2Bt%8BHejw~~yQp1p{IKP_zJ3!Oq7|+)Ds@pyQ_64-$*ww>zN_2t5'
    b'o6k+215Gr)oYa5_P2;!g`oDgxp@9XFqjZ0x0m6TN5EZEvT?mtyP@QR*?VdVxiqkI%LqCL_04'
    b'8HcMK?Ej3afNs@Qs2L9gev&tW=$BmQbP*Gs+reQAWKocl|u*?5E^;`<qa9m|E&NKq1GAK$lC'
    b'4gp*7+h$GLJ;1nx8-No(Y%o*@?nBP8sE3D2`G3|+d)3Ul+wliQ~7A9gsR8N!>nL@g}ZSFIE<'
    b'3m(pl;5Ur1C9Mqcuyh-kf^e??xt{`a4E{mmds6mf6NUP&GKgkxYRM(g}FU5>lb>wTQ(m8dsL'
    b'{N-YuOa>4c3fm+n`!MpQ_(c6FmIq5-rI5_=(FhR{10ek%v;Pb!Y9)b1iKktnF@^w8;oP<S57'
    b'B-quZtTE=3L>_6TdPcc0A*;>4w-Y=gs%Z@-EDdv0g4m8a#V|5<Zt;?(@wYrVb-Mk1Zdw%Y09'
    b'Gn=e1&7;wA~N&ryFEU*V)J&^KvQY@Ak>Zm{0ooZsRK7?-#1(gu$iVqGdslP=0S|Q3<Fa-xec'
    b'8uu5r%nQ4UlsMx^Vni(7Bskl7aQdNJe>Db2}fWQ}$geIyG@D7n&OyNG7>c!_70Cy>lzy?L6p'
    b'<=%0-^CQkVI#_teeId#xO_L^xsUL?ycSIzlppqI74YA6(Zt6g{fFa6gQ(#f&Xs(UOr7@lz7L'
    b'Xc%_<xA_oa^vO}LkvmhHHq%Qe_z3^am;#oZ~$FtL3o@Cl{K^hF6+CUh+JE8-<96BRbQ2sw+0'
    b'07hXrCaq6ZRIn6iVjyQ^ufxm4gbLmXnMgIjh?7(|D&?Nlb2S%9rK@)Jz_irCdm`I{$-zZLXJ'
    b'v!RG$;h}KR@@r7eX*74~#4FYiyZBtxv8w`%IDomf2+mQ=p-v-~~BnB4ky$7MTefMN~%ZLb%`'
    b'9HAuZy>YC5wbuq}fsUv>XN>?<(K|l9W_i0*$<>pocq&1w+=2XX=ZTZ!b+9?|3)6=`R%F!}Z&'
    b'a3Qm#HB{fW|T^Vk!~MbAjB%uoKE2KB?<{2C4_7P^XpCPOvLvb*=`u!@U??9&!FwtogjvKchT'
    b'JYXIjeMr`}Q^G8vJ%n;<f;*!&FZ!Ihx~1V$NR`5Y3LJT5Gs{MWKOM$(1PgZT`{b##@>Y~@{s'
    b')vnA~VaZp}VEy{WN=0EzUX~N5K4PI_3hVd(<@S@?%#NnfV#o&CTj&LSlM;dAJ}n;7UKjmt%e'
    b'cG-MV+#m^)RYoItH4F4SpRv>o$*ci&39VZ{Gn)82#qhvYI77MY6k>v2iQs00000F``J)J91k'
    b'700D*!s38CVB-0#!vBYQl0ssI200dcD'
    )

def load_py_ico():
    return load_ico_lzma_b85(_py_icon)

################################################################################

_ctwin32_icon = (
    b'{Wp48S^xk9=GL@E0stWa761SMbT8$j;0UJ#&0PQ#05Aj)f+J6yaHvHu1q>Gs(yZ)`rT4VqYn'
    b'%B-HIH~>jeV{SNI_{JHVRTYsiKzK7CwQ=tJ2Ks!~srhl-I*p0o!hI-fpo^97Xi*4Q!Dd3X}v'
    b'$8WKulmA{F!7oZCs)IAY;ZLMh6_No@b0ca=PkNzVlN3cC!ob60RrU0=4ndqroAy}qIF?$;ZH'
    b'Ufdr4QqNydBJoi**2(b>LJtsq1--PQVunbK*nFuD0^<0YG0-)S3tS_@5y)&cQ=s^k)-n~=oM'
    b'02WzYUu?pZecGjm&)ry+Orfv<jRMfx!kc1P+ahYuS(p%J>Y|E(NvE5ZQb(61)+uYPYcZKA?4'
    b'y3*?c3~|o@e>T)A&e2>Qsiwrg(x})20YiS)c@q~frD|ufg|rFed$7w!;pG&;vB0orztE80g1'
    b'5I$1~{%oA8kJqG8F5WFuF%de0KZlqk)<^C2K?eE3mj3mf16t&%ma@|F%17nc2|)O8_#Lldac'
    b'FKC#?m7Ga6mIU+oCQ4>>QHY^>Au-AQr)+1y^BmO-flIkHJsV)N);I;ebT<`hX9)46w<Rg3FL'
    b'i)nM%7pg~SO#qz-ze-1-*zMpUl#X<!?Q_$_PfG77v&?(kBe4H7IG?zCE?~%aW3h~O~Nk#)1H'
    b'v=0R1#>@CNEYYT5RzSq>D#w>P>#BfdIYc)Z?l^6ml~-ykX8X8NnIqKq+G;v$hN(Y<Jt)r?c9'
    b'>GCHY0zJilG#Dgj6g&_Ar1vUBMuh7e1c=)&+mJs_S(AEH(w+z@wOPz`09ec$bD^<B20sPmtQ'
    b';9O8ejb}|4A@5yHoQ|la1UXI=fK{SBk8E0dNDC-7yw%?a9h+@fRDw!w6q>w{eR6p%f9?J2ey'
    b'sbWHE%E5LjOC=}=%xLInY)d36&`<eV73u+U8SBisPCILL$*_AbshRHS~A(Eo9HFi__M)NO{L'
    b'k}hiLF?7EhWwHZo$Xt984N&;?2^{2k^@GcRUbM$+nhqIJ0$;#L=XESY=_B_hRlCH6Hx-@ItE'
    b'@4C^*r-Z*y%%>?H81t0$s$1c97#vHl%HhMw%^^5Tid??!_#@o>WP7mN#K1i21pownz?8>#_R'
    b'67v0mi1&j!iRKMdj-fwjC}mJ4deM2@pDkT)?qtiS1a~80#D^R~9XM3@7QZL?zs-ZA-pCJo6{'
    b'R>GbdV}c`%kbaf1&ZpLT&u%w>OgdQZ*~7)q(fpFA=qdeAt|9=O5NX(*%bl8iYPJ(FJbra1Lc'
    b'1<m23X?h%S;!h}bzIodaWjLg}aLqJ_oc`_kb`^egLfTdLSI6#rFaK)MtiwsG%!qr%(+$M7=i'
    b'FsygaUfDcG1`f1)_y!(vw(U!A(ly-<MbTl&@rjG$BKX<x{({u@XJ*QsEUvq@f(bmc6v=U8!5'
    b'}p{K5@GE7Jm9Z!Bv3CFo#1ZHV7*nTNaA10bQO+6x22LetMJ2b#}!7h6#~GL*UD=`~w_>msdT'
    b'YdUl6{}zNFtK;1wkl9@$K|*;m;I}jOF`7rfqE9`8A2}5MAYGOm&Bd@13Bgk?!sLhcJ65PFvq'
    b'EK-oczoVl#{I->+Rapc9fQ>LT)>~&`%W3cz@D3$X)<L+qpZSQ4LslJyc~^rDkdX00000gHzk'
    b'KXFSSV00HR<s1X1FO9VA)vBYQl0ssI200dcD'
    )

def load_ctwin32_ico():
    return load_ico_lzma_b85(_ctwin32_icon)

################################################################################
