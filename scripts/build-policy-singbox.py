#!/usr/bin/env python3
"""Integrate the UUID gate into a disposable, pinned sing-box v1.13.15 checkout.
Never run this against an installed binary or production source directory.
Usage: build-policy-singbox.py /disposable/sing-box /tzsing-source
"""
import sys, subprocess
from pathlib import Path
root=Path(sys.argv[1]); module=Path(sys.argv[2]).resolve()
if subprocess.check_output(['git','-C',str(root),'describe','--tags','--exact-match'],text=True).strip()!='v1.13.15': raise SystemExit('requires disposable upstream v1.13.15 checkout')
if 'tzsingbox/policy' in (root/'protocol/vless/inbound.go').read_text():raise SystemExit('already integrated')
p=root/'experimental/clashapi/trafficontrol/tracker.go';s=p.read_text()
if 'tzsingbox/policy' in s:raise SystemExit('already integrated')
needle='"sourceIP":        t.Metadata.Source.Addr,'
assert needle in s
s=s.replace(needle,'"inboundUser": t.Metadata.User,\n'+needle);p.write_text(s)
p=root/'protocol/vless/inbound.go';s=p.read_text()
s=s.replace('"os"','"os"\n"tzsingbox/policy"\n"github.com/sagernet/sing/common/buf"')
needle='\tinbound := &Inbound{';assert needle in s
s=s.replace(needle,''' if _,e:=policy.Runtime();e!=nil{return nil,e}
 for _,u:=range options.Users { if e:=policy.Register(tag,u.Name,u.UUID);e!=nil{return nil,e} }
'''+needle,1)
needle='\t\treturn h.listener.Start()';assert s.count(needle)==1
s=s.replace(needle,'if e:=h.listener.Start();e!=nil{return e};l,e:=policy.Runtime();if e!=nil{return e};if l!=nil{return l.MarkInboundStarted(h.Tag())};return nil')
needle='\th.router.RouteConnectionEx(ctx, conn, metadata, onClose)';assert s.count(needle)==1
s=s.replace(needle,''' identity:=policy.Identity(metadata.Inbound,metadata.User)
 if e:=policy.Admit(metadata.Inbound,identity,0);e!=nil{N.CloseOnHandshakeFailure(conn,onClose,e);return}
 conn=policy.Wrap(conn,metadata.Inbound,identity)
'''+needle)
needle='\th.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)';assert s.count(needle)==1
s=s.replace(needle,''' identity:=policy.Identity(metadata.Inbound,metadata.User)
 if e:=policy.Admit(metadata.Inbound,identity,0);e!=nil{conn.Close();return}
 if os.Getenv("TZSING_POLICY_DB")!="" {conn=&policyPacket{PacketConn:conn,in:metadata.Inbound,user:identity}}
'''+needle)
s+='''
// This gate is at the authenticated VLESS boundary, independent of Clash API.
// No replaceable-reader/Upstream hooks are exposed to optimized copy paths.
type policyPacket struct {N.PacketConn;in,user string}
func(c *policyPacket)FrontHeadroom()int{return N.CalculateFrontHeadroom(c.PacketConn)}
func(c *policyPacket)RearHeadroom()int{return N.CalculateRearHeadroom(c.PacketConn)}
func(c *policyPacket)ReadPacket(b *buf.Buffer)(M.Socksaddr,error){
 a,e:=c.PacketConn.ReadPacket(b);if e!=nil{return a,e};size:=int64(b.Len())
 if size==0{return a,policy.Admit(c.in,c.user,0)}
 l,e:=policy.Runtime();if e!=nil{return a,e};if l==nil{return a,nil}
 r,e:=l.Reserve(c.in,c.user,"upload",size);if e!=nil{return a,e}
 if r.Amount!=size{l.Settle(r.Token,0);return a,policy.ErrDenied}
 if e=l.Settle(r.Token,size);e!=nil{c.PacketConn.Close()};return a,e
}
func(c *policyPacket)WritePacket(b *buf.Buffer,a M.Socksaddr)error{
 size:=int64(b.Len());if size==0{if e:=policy.Admit(c.in,c.user,0);e!=nil{b.Release();return e};return c.PacketConn.WritePacket(b,a)}
 l,e:=policy.Runtime();if e!=nil{b.Release();return e};if l==nil{return c.PacketConn.WritePacket(b,a)}
 r,e:=l.Reserve(c.in,c.user,"download",size);if e!=nil{b.Release();return e}
 if r.Amount!=size{l.Settle(r.Token,0);b.Release();return policy.ErrDenied}
 if e=c.PacketConn.WritePacket(b,a);e!=nil{return e}
 return l.Settle(r.Token,size)
}
'''
p.write_text(s)
p=root/'go.mod';s=p.read_text();s+='\nrequire tzsingbox v0.0.0\nreplace tzsingbox => '+str(module)+'\n';p.write_text(s)
