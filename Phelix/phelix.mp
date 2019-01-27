
% pHelix figure source
% Copyright (c) 2002 by MacFergus BV
% Created by Niels Ferguson
% Copyright (c) 2004 by Hifn
% Updated by Doug Whting
%
input ntfbox

DOT_SIZE = 2.5 pt;    % size of connection dots (0pt --> none)

u = 1mm;
xor_radius = 2mm;

boxsep = 5u;

def newxor( suffix self ) =
  makebx( self )("");
  self.width = self.height = xor_radius * 2;
  self.corner_radius = xor_radius;
enddef;

def drawxor( suffix self ) =
  drawbx( self );
  draw self.n -- self.s;
  draw self.e -- self.w;
enddef;

def newadd( suffix self ) =
  makebx( self )("");
  self.width = self.height = xor_radius * 2;
enddef;

def drawadd( suffix self ) = drawxor( self ) enddef;


beginfig( 1 );

x4-x3 = x3-x2 = x2-x1 = x1-x0; x0=0;
makebx( rotsize, btex $\vphantom E <\!\!<\!\!< 22$ etex );
fixsizebx( rotsize );

x9 = x0 - 0.5*rotsize.width - 3u;

x1 - x0 = 8*xor_radius;

b = 0 - 3u;
newadd( add_c );
add_c.hmid = x0;
add_c.top = b - 4u;
makebx( rot_d, btex $\vphantom E <\!\!<\!\!< 15$ etex );
rot_d.width = rotsize.width;
fixsizebx( rot_d );
rot_d.n = (x3,add_c.vmid - 4u);
newadd( add_e );
add_e.hmid = x1;
add_e.vmid = rot_d.bot - 3u;
makebx( rot_f, btex $\vphantom E <\!\!<\!\!< 25$ etex );
rot_f.width = rotsize.width;
fixsizebx( rot_f );
rot_f.n = (x4,add_e.vmid - 4u);
newxor( xor_g );
xor_g.hmid = x2;
xor_g.vmid = add_e.bot - 3u;
makebx( rot_h, btex $\vphantom E <\!\!<\!\!< 9$ etex );
rot_h.width = rotsize.width;
fixsizebx( rot_h );
rot_h.n = (x0,xor_g.vmid - 4u);
newxor( xor_i );
xor_i.hmid = x3;
xor_i.vmid = xor_g.bot - 3u;
makebx( rot_j, btex $\vphantom E <\!\!<\!\!< 10$ etex );
rot_j.width = rotsize.width;
fixsizebx( rot_j );
rot_j.n = (x1,xor_i.vmid - 4u);
newadd( add_ba );
add_ba.hmid = x4;
add_ba.vmid = xor_i.bot - 3u;
makebx( rot_bb, btex $\vphantom E <\!\!<\!\!< 17$ etex );
rot_bb.width = rotsize.width;
fixsizebx( rot_bb );
rot_bb.n = (x2,add_ba.vmid - 4u);
newxor( xor_bd );
newadd( add_bc );
xor_bd.hmid = x0;
add_bc.hmid = 0.5[x0,x1];
be = add_bc.top + 3u;
add_bc.vmid = xor_bd.vmid;
fixsizebx( add_bc );
fixsizebx( xor_bd );
xor_bd.vmid = rot_bb.bot - 3u;
makebx( rot_bf, btex $\vphantom E <\!\!<\!\!< 30$ etex );
rot_bf.width = rotsize.width;
fixsizebx( rot_bf );
rot_bf.n = (x3,add_bc.vmid - 4u);
newxor( xor_bg );
xor_bg.hmid = x1;
xor_bg.vmid = rot_bf.bot - 3u;
makebx( rot_bh, btex $\vphantom E <\!\!<\!\!< 13$ etex );
rot_bh.width = rotsize.width;
fixsizebx( rot_bh );
rot_bh.n = (x4,xor_bg.vmid - 4u);
newadd( add_bi );
add_bi.hmid = x2;
add_bi.vmid = xor_bg.bot - 3u;
makebx( rot_bj, btex $\vphantom E <\!\!<\!\!< 20$ etex );
rot_bj.width = rotsize.width;
fixsizebx( rot_bj );
rot_bj.n = (x0,add_bi.vmid - 4u);
newadd( add_ca );
add_ca.hmid = x3;
add_ca.vmid = add_bi.bot - 3u;
makebx( rot_cb, btex $\vphantom E <\!\!<\!\!< 11$ etex );
rot_cb.width = rotsize.width;
fixsizebx( rot_cb );
rot_cb.n = (x1,add_ca.vmid - 4u);
newxor( xor_cc );
xor_cc.hmid = x4;
xor_cc.vmid = add_ca.bot - 3u;
makebx( rot_cd, btex $\vphantom E <\!\!<\!\!< 5$ etex );
rot_cd.width = rotsize.width;
fixsizebx( rot_cd );
rot_cd.n = (x2,xor_cc.vmid - 4u);
newadd( add_cf );
newxor( xor_ce );
add_cf.hmid = x0;
xor_ce.hmid = 0.5[x0,x1];
cg = xor_ce.top + 3u;
xor_ce.vmid = add_cf.vmid;
fixsizebx( xor_ce );
fixsizebx( add_cf );
add_cf.vmid = rot_cd.bot - 3u;
makebx( rot_ch, btex $\vphantom E <\!\!<\!\!< 15$ etex );
rot_ch.width = rotsize.width;
fixsizebx( rot_ch );
rot_ch.n = (x3,xor_ce.vmid - 4u);
newadd( add_ci );
add_ci.hmid = x1;
add_ci.vmid = rot_ch.bot - 3u;
makebx( rot_cj, btex $\vphantom E <\!\!<\!\!< 25$ etex );
rot_cj.width = rotsize.width;
fixsizebx( rot_cj );
rot_cj.n = (x4,add_ci.vmid - 4u);
newxor( xor_da );
xor_da.hmid = x2;
xor_da.vmid = add_ci.bot - 3u;
makebx( rot_db, btex $\vphantom E <\!\!<\!\!< 9$ etex );
rot_db.width = rotsize.width;
fixsizebx( rot_db );
rot_db.n = (x0,xor_da.vmid - 4u);
newxor( xor_dc );
xor_dc.hmid = x3;
xor_dc.vmid = xor_da.bot - 3u;
makebx( rot_dd, btex $\vphantom E <\!\!<\!\!< 10$ etex );
rot_dd.width = rotsize.width;
fixsizebx( rot_dd );
rot_dd.n = (x1,xor_dc.vmid - 4u);
newadd( add_de );
add_de.hmid = x4;
add_de.vmid = xor_dc.bot - 3u;
makebx( rot_df, btex $\vphantom E <\!\!<\!\!< 17$ etex );
rot_df.width = rotsize.width;
fixsizebx( rot_df );
rot_df.n = (x2,add_de.vmid - 4u);
newxor( xor_dh );
newadd( add_dg );
xor_dh.hmid = x0;
add_dg.hmid = 0.5[x0,x1];
di = add_dg.top + 3u;
add_dg.vmid = xor_dh.vmid;
fixsizebx( add_dg );
fixsizebx( xor_dh );
xor_dh.vmid = rot_df.bot - 3u;
makebx( rot_dj, btex $\vphantom E <\!\!<\!\!< 30$ etex );
rot_dj.width = rotsize.width;
fixsizebx( rot_dj );
rot_dj.n = (x3,add_dg.vmid - 4u);
newxor( xor_ea );
xor_ea.hmid = x1;
xor_ea.vmid = rot_dj.bot - 3u;
makebx( rot_eb, btex $\vphantom E <\!\!<\!\!< 13$ etex );
rot_eb.width = rotsize.width;
fixsizebx( rot_eb );
rot_eb.n = (x4,xor_ea.vmid - 4u);
newadd( add_ec );
add_ec.hmid = x2;
add_ec.vmid = xor_ea.bot - 3u;
makebx( rot_ed, btex $\vphantom E <\!\!<\!\!< 20$ etex );
rot_ed.width = rotsize.width;
fixsizebx( rot_ed );
rot_ed.n = (x0,add_ec.vmid - 4u);
newadd( add_ee );
add_ee.hmid = x3;
add_ee.vmid = add_ec.bot - 3u;
makebx( rot_ef, btex $\vphantom E <\!\!<\!\!< 11$ etex );
rot_ef.width = rotsize.width;
fixsizebx( rot_ef );
rot_ef.n = (x1,add_ee.vmid - 4u);
newxor( xor_eg );
xor_eg.hmid = x4;
xor_eg.vmid = add_ee.bot - 3u;
makebx( rot_eh, btex $\vphantom E <\!\!<\!\!< 5$ etex );
rot_eh.width = rotsize.width;
fixsizebx( rot_eh );
rot_eh.n = (x2,xor_eg.vmid - 4u);

label.top( btex $Z^{(i)}_0$ etex, (x0,0) );
label.top( btex $Z^{(i)}_1$ etex, (x1,0) );
label.top( btex $Z^{(i)}_2$ etex, (x2,0) );
label.top( btex $Z^{(i)}_3$ etex, (x3,0) );
label.top( btex $Z^{(i)}_4$ etex, (x4,0) );
draw (x0,0)--(x0,b);
%----------- old output function (DLW)
%drawarrow (x0,b)--(x9,b);
%label.lft( btex key stream $S_i$ etex, (x9,b) );
%-----------
drawadd( add_c );
drawarrow (x0,b)--(x0,add_c.top);
draw (x3,0)--(x3,add_c.vmid);
drawarrow (x3,add_c.vmid)--add_c.e;
drawbx( rot_d );
drawarrow (x3,add_c.vmid)--(x3,rot_d.top);
drawadd( add_e );
drawarrow (x1,0)--(x1,add_e.top);
draw (x4,0)--(x4,add_e.vmid);
drawarrow (x4,add_e.vmid)--add_e.e;
drawbx( rot_f );
drawarrow (x4,add_e.vmid)--(x4,rot_f.top);
drawxor( xor_g );
drawarrow (x2,0)--(x2,xor_g.top);
draw (x0,add_c.bot)--(x0,xor_g.vmid);
drawarrow (x0,xor_g.vmid)--xor_g.w;
drawbx( rot_h );
drawarrow (x0,xor_g.vmid)--(x0,rot_h.top);
drawxor( xor_i );
drawarrow (x3,rot_d.bot)--(x3,xor_i.top);
draw (x1,add_e.bot)--(x1,xor_i.vmid);
drawarrow (x1,xor_i.vmid)--xor_i.w;
drawbx( rot_j );
drawarrow (x1,xor_i.vmid)--(x1,rot_j.top);
drawadd( add_ba );
drawarrow (x4,rot_f.bot)--(x4,add_ba.top);
draw (x2,xor_g.bot)--(x2,add_ba.vmid);
drawarrow (x2,add_ba.vmid)--add_ba.w;
drawbx( rot_bb );
drawarrow (x2,add_ba.vmid)--(x2,rot_bb.top);
drawadd( add_bc );
drawxor( xor_bd );
drawarrow (x0,rot_h.bot)--(x0,xor_bd.top);
draw (x3,xor_i.bot)--(x3,add_bc.vmid);
drawarrow (x3,add_bc.vmid)--add_bc.e;
drawarrow add_bc.e--xor_bd.e;
drawarrow (x9,be)--(add_bc.hmid,be)--add_bc.n;
label.lft( btex key $X_{i,0}$ etex, (x9,be) );
drawbx( rot_bf );
drawarrow (x3,add_bc.vmid)--(x3,rot_bf.top);
drawxor( xor_bg );
drawarrow (x1,rot_j.bot)--(x1,xor_bg.top);
draw (x4,add_ba.bot)--(x4,xor_bg.vmid);
drawarrow (x4,xor_bg.vmid)--xor_bg.e;
drawbx( rot_bh );
drawarrow (x4,xor_bg.vmid)--(x4,rot_bh.top);
drawadd( add_bi );
drawarrow (x2,rot_bb.bot)--(x2,add_bi.top);
draw (x0,xor_bd.bot)--(x0,add_bi.vmid);
drawarrow (x0,add_bi.vmid)--add_bi.w;
drawbx( rot_bj );
drawarrow (x0,add_bi.vmid)--(x0,rot_bj.top);
drawadd( add_ca );
drawarrow (x3,rot_bf.bot)--(x3,add_ca.top);
draw (x1,xor_bg.bot)--(x1,add_ca.vmid);
drawarrow (x1,add_ca.vmid)--add_ca.w;
drawbx( rot_cb );
drawarrow (x1,add_ca.vmid)--(x1,rot_cb.top);
drawxor( xor_cc );
drawarrow (x4,rot_bh.bot)--(x4,xor_cc.top);
draw (x2,add_bi.bot)--(x2,xor_cc.vmid);
drawarrow (x2,xor_cc.vmid)--xor_cc.w;
drawbx( rot_cd );
drawarrow (x2,xor_cc.vmid)--(x2,rot_cd.top);
drawxor( xor_ce );
drawadd( add_cf );
drawarrow (x0,rot_bj.bot)--(x0,add_cf.top);
draw (x3,add_ca.bot)--(x3,xor_ce.vmid);
drawarrow (x3,xor_ce.vmid)--xor_ce.e;
drawarrow xor_ce.e--add_cf.e;
drawarrow (x9,cg)--(xor_ce.hmid,cg)--xor_ce.n;
label.lft( btex plaintext $P_i$ etex, (x9,cg) );
drawbx( rot_ch );
drawarrow (x3,xor_ce.vmid)--(x3,rot_ch.top);
drawadd( add_ci );
drawarrow (x1,rot_cb.bot)--(x1,add_ci.top);
draw (x4,xor_cc.bot)--(x4,add_ci.vmid);
drawarrow (x4,add_ci.vmid)--add_ci.e;
drawbx( rot_cj );
drawarrow (x4,add_ci.vmid)--(x4,rot_cj.top);
drawxor( xor_da );
drawarrow (x2,rot_cd.bot)--(x2,xor_da.top);
draw (x0,add_cf.bot)--(x0,xor_da.vmid);
drawarrow (x0,xor_da.vmid)--xor_da.w;
drawbx( rot_db );
drawarrow (x0,xor_da.vmid)--(x0,rot_db.top);
drawxor( xor_dc );
drawarrow (x3,rot_ch.bot)--(x3,xor_dc.top);
draw (x1,add_ci.bot)--(x1,xor_dc.vmid);
drawarrow (x1,xor_dc.vmid)--xor_dc.w;
drawbx( rot_dd );
drawarrow (x1,xor_dc.vmid)--(x1,rot_dd.top);
drawadd( add_de );
drawarrow (x4,rot_cj.bot)--(x4,add_de.top);
draw (x2,xor_da.bot)--(x2,add_de.vmid);
drawarrow (x2,add_de.vmid)--add_de.w;
drawbx( rot_df );
drawarrow (x2,add_de.vmid)--(x2,rot_df.top);
drawadd( add_dg );
drawxor( xor_dh );
drawarrow (x0,rot_db.bot)--(x0,xor_dh.top);
draw (x3,xor_dc.bot)--(x3,add_dg.vmid);
drawarrow (x3,add_dg.vmid)--add_dg.e;
drawarrow add_dg.e--xor_dh.e;
drawarrow (x9,di)--(add_dg.hmid,di)--add_dg.n;
label.lft( btex key $X_{i,1}$ etex, (x9,di) );
drawbx( rot_dj );
drawarrow (x3,add_dg.vmid)--(x3,rot_dj.top);
drawxor( xor_ea );
drawarrow (x1,rot_dd.bot)--(x1,xor_ea.top);
draw (x4,add_de.bot)--(x4,xor_ea.vmid);
drawarrow (x4,xor_ea.vmid)--xor_ea.e;
drawbx( rot_eb );
drawarrow (x4,xor_ea.vmid)--(x4,rot_eb.top);
drawadd( add_ec );
drawarrow (x2,rot_df.bot)--(x2,add_ec.top);
draw (x0,xor_dh.bot)--(x0,add_ec.vmid);
drawarrow (x0,add_ec.vmid)--add_ec.w;
drawbx( rot_ed );
drawarrow (x0,add_ec.vmid)--(x0,rot_ed.top);
drawadd( add_ee );
drawarrow (x3,rot_dj.bot)--(x3,add_ee.top);
draw (x1,xor_ea.bot)--(x1,add_ee.vmid);
drawarrow (x1,add_ee.vmid)--add_ee.w;
drawbx( rot_ef );
drawarrow (x1,add_ee.vmid)--(x1,rot_ef.top);
drawxor( xor_eg );
drawarrow (x4,rot_eb.bot)--(x4,xor_eg.top);
draw (x2,add_ec.bot)--(x2,xor_eg.vmid);
drawarrow (x2,xor_eg.vmid)--xor_eg.w;
drawbx( rot_eh );
drawarrow (x2,xor_eg.vmid)--(x2,rot_eh.top);
draw (x0,rot_ed.bot)--(x0,rot_eh.bot);
draw (x1,rot_ef.bot)--(x1,rot_eh.bot);
draw (x2,rot_eh.bot)--(x2,rot_eh.bot);
draw (x3,add_ee.bot)--(x3,rot_eh.bot);
draw (x4,xor_eg.bot)--(x4,rot_eh.bot);
drawarrow (x0,rot_eh.bot)--(x0,rot_eh.bot-5u);
drawarrow (x1,rot_eh.bot)--(x1,rot_eh.bot-5u);
drawarrow (x2,rot_eh.bot)--(x2,rot_eh.bot-5u);
drawarrow (x3,rot_eh.bot)--(x3,rot_eh.bot-5u);
drawarrow (x4,rot_eh.bot)--(x4,rot_eh.bot-5u);
label.bot( btex $Z^{(i+1)}_0$ etex, (x0,rot_eh.bot-5u) );
label.bot( btex $Z^{(i+1)}_1$ etex, (x1,rot_eh.bot-5u) );
label.bot( btex $Z^{(i+1)}_2$ etex, (x2,rot_eh.bot-5u) );
label.bot( btex $Z^{(i+1)}_3$ etex, (x3,rot_eh.bot-5u) );
label.bot( btex $Z^{(i+1)}_4$ etex, (x4,rot_eh.bot-5u) );
%----------- new output function ---------------
x10 = x4 + 0.5*rotsize.width + 2*xor_radius;
y10 = cg;
label.rt( btex $Y^{(i)}_4$ etex, (x4,y10-2*xor_radius) );
newadd( add_out );	% the output keystream adder
add_out.hmid = x10;
add_out.vmid = y10;
drawadd( add_out );
x11 = add_out.rt + 3*xor_radius;
x12 = x11 + 2*xor_radius;
y12 = y10 + 5*xor_radius;
drawarrow (x4,y10)--(add_out.lft,y10);
drawarrow (add_out.rt,y10)--(x11,y10);
label.rt( btex keystream $S_i$ etex, (x11,y10) );
label.rt( btex $Z^{(i-4)}_4$ etex, (x12,y12) );
drawarrow (x12,y12)--(add_out.hmid,y12)--(add_out.hmid,add_out.top);
% put some  connection dots in (if non-zero pen width)
pickup pencircle scaled DOT_SIZE; % set pen width for dots
draw (x4,y10);
draw (x3,add_c.vmid);	draw (x3,xor_bd.vmid);
draw (x4,add_e.vmid);	draw (x4,xor_bg.vmid);
draw (x0,xor_g.vmid);	draw (x0,add_bi.vmid);
draw (x1,xor_i.vmid);	draw (x1,add_ca.vmid);
draw (x2,add_ba.vmid);	draw (x2,xor_cc.vmid);

draw (x3,add_cf.vmid);	draw (x3,xor_dh.vmid);
draw (x4,add_ci.vmid);	draw (x4,xor_ea.vmid);
draw (x0,xor_da.vmid);	draw (x0,add_ec.vmid);
draw (x1,xor_dc.vmid);	draw (x1,add_ee.vmid);
draw (x2,add_de.vmid);	draw (x2,xor_eg.vmid);
%-----------------------------------------------
endfig;

beginfig( 2 );

x4-x3 = x3-x2 = x2-x1 = x1-x0; x0=0;
makebx( rotsize, btex $\vphantom E <\!\!<\!\!< 22$ etex );
fixsizebx( rotsize );

x9 = x0 - 0.5*rotsize.width - 3u;

x1 - x0 = 8*xor_radius;

newadd( add_ei );
add_ei.hmid = x1;
add_ei.top = rot_eh.bot-5u - 4u;
makebx( rot_ej, btex $\vphantom E <\!\!<\!\!< a$ etex );
rot_ej.width = rotsize.width;
fixsizebx( rot_ej );
rot_ej.n = (x0,add_ei.vmid - 4u);

drawadd( add_ei );
drawarrow (x1,rot_eh.bot-5u)--(x1,add_ei.top);
draw (x0,rot_eh.bot-5u)--(x0,add_ei.vmid);
drawarrow (x0,add_ei.vmid)--add_ei.w;
drawbx( rot_ej );
drawarrow (x0,add_ei.vmid)--(x0,rot_ej.top);
draw (x0,rot_ej.bot)--(x0,rot_ej.bot);
draw (x1,add_ei.bot)--(x1,rot_ej.bot);
draw (x2,rot_eh.bot-5u)--(x2,rot_ej.bot);
draw (x3,rot_eh.bot-5u)--(x3,rot_ej.bot);
draw (x4,rot_eh.bot-5u)--(x4,rot_ej.bot);
drawarrow (x0,rot_ej.bot)--(x0,rot_ej.bot-5u);
drawarrow (x1,rot_ej.bot)--(x1,rot_ej.bot-5u);
drawarrow (x2,rot_ej.bot)--(x2,rot_ej.bot-5u);
drawarrow (x3,rot_ej.bot)--(x3,rot_ej.bot-5u);
drawarrow (x4,rot_ej.bot)--(x4,rot_ej.bot-5u);

pickup pencircle scaled DOT_SIZE; % set pen width for dots
draw (x0,add_ei.vmid);

endfig;

end
