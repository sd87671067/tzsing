#!/usr/bin/env python3
"""Patch a disposable upstream sing-box 1.13.15 checkout, preserving its config and protocol logic.
Usage: build-policy-singbox.py /path/to/disposable/sing-box /path/to/tzsing
Then: go mod tidy && go build -tags with_clash_api,with_quic,with_utls ...
"""
import sys, subprocess
from pathlib import Path
root=Path(sys.argv[1]); module=Path(sys.argv[2]).resolve()
if subprocess.check_output(['git','-C',str(root),'describe','--tags','--exact-match'],text=True).strip()!='v1.13.15': raise SystemExit('requires disposable upstream v1.13.15 checkout')
p=root/'experimental/clashapi/trafficontrol/tracker.go'
s=p.read_text()
if 'tzsingbox/policy' in s: raise SystemExit('already integrated')
s=s.replace('"net"','"net"\n"os"\n"tzsingbox/policy"\n"github.com/sagernet/sing/common/buf"\nM "github.com/sagernet/sing/common/metadata"')
s=s.replace('"sourceIP":        t.Metadata.Source.Addr,','"inboundUser": t.Metadata.User,\n"sourceIP":        t.Metadata.Source.Addr,')
s=s.replace('id, _ := uuid.NewV4()','conn = policy.Wrap(conn, metadata.Inbound, policy.Identity(metadata.Inbound,metadata.User))\n id, _ := uuid.NewV4()',1)
pos=s.index('func NewUDPTracker(')
s=s[:pos]+s[pos:].replace('id, _ := uuid.NewV4()','if metadata.User != "" { conn = &policyPacket{PacketConn:conn,in:metadata.Inbound,user:policy.Identity(metadata.Inbound,metadata.User)}; if policy.Admit(metadata.Inbound,policy.Identity(metadata.Inbound,metadata.User),0)!=nil { conn.Close() } }\n id, _ := uuid.NewV4()',1)
s+='''
func init(){if len(os.Args)>1&&os.Args[1]=="run"{policy.Runtime()}}
// Standard packet wrapper deliberately exposes no bypass or replaceable hooks.
type policyPacket struct {N.PacketConn;in,user string}
func(c *policyPacket)ReadPacket(b *buf.Buffer)(M.Socksaddr,error){
 l,e:=policy.Runtime();if e!=nil{return M.Socksaddr{},e};if l==nil{return c.PacketConn.ReadPacket(b)}
 r,e:=l.Reserve(c.in,c.user,"upload",65536);if e!=nil{return M.Socksaddr{},e}
 a,e:=c.PacketConn.ReadPacket(b)
 if int64(b.Len())>r.Amount{c.PacketConn.Close();return M.Socksaddr{},policy.ErrDenied}
 if x:=l.Settle(r.Token,int64(b.Len()));x!=nil{c.PacketConn.Close();return M.Socksaddr{},x};return a,e
}
func(c *policyPacket)WritePacket(b *buf.Buffer,a M.Socksaddr)error{
 l,e:=policy.Runtime();if e!=nil{b.Release();return e};if l==nil{return c.PacketConn.WritePacket(b,a)}
 size:=int64(b.Len());r,e:=l.Reserve(c.in,c.user,"download",size);if e!=nil{b.Release();return e}
 if r.Amount!=size{l.Settle(r.Token,0);b.Release();return policy.ErrDenied}
 if e=c.PacketConn.WritePacket(b,a);e!=nil{return e}
 return l.Settle(r.Token,size)
}
'''
p.write_text(s)
p=root/'protocol/vless/inbound.go'
s=p.read_text().replace('"os"','"os"\n"tzsingbox/policy"')
needle='\tinbound := &Inbound{'
assert needle in s
s=s.replace(needle,'\tfor _,u:=range options.Users { if e:=policy.Register(tag,u.Name,u.UUID);e!=nil{return nil,e} }\n'+needle,1)
p.write_text(s)
p=root/'go.mod';s=p.read_text();s+='\nrequire tzsingbox v0.0.0\nreplace tzsingbox => '+str(module)+'\n';p.write_text(s)
