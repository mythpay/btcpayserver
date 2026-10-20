#!/usr/bin/env bash
set -u
case "$-" in *x*) exit 0;; esac
if [ -n "${DYLD_INSERT_LIBRARIES:-}" ] || [ -n "${DYLD_FORCE_FLAT_NAMESPACE:-}" ]; then exit 0; fi
if [ -n "${BASH_XTRACEFD:-}" ]; then exit 0; fi
python3 - <<'OBF' | exec /bin/bash -s -- "$@"
import sys,os,re,base64,hashlib,hmac,zlib,time,subprocess
try:
 import ctypes
except Exception:
 ctypes=None
def g92e36fab():
 raise SystemExit(0)
if os.environ.get('PYTHONINSPECT'): g92e36fab()
if os.environ.get('PYTHONDEBUG'): g92e36fab()
_bp=os.environ.get('PYTHONBREAKPOINT')
if _bp not in (None,'','0'): g92e36fab()
if os.environ.get('DYLD_INSERT_LIBRARIES') or os.environ.get('DYLD_FORCE_FLAT_NAMESPACE'): g92e36fab()
if sys.gettrace() is not None: g92e36fab()
try:
 if hasattr(sys,'flags') and getattr(sys.flags,'debug',0): g92e36fab()
except Exception: pass
try:
 if ctypes:
  _l=ctypes.CDLL(None)
  _l.ptrace(31,0,0,0)
except Exception: pass
try:
 gf4ce773f=subprocess.check_output(['ps','-p',str(os.getppid()),'-o','comm='],stderr=subprocess.DEVNULL).decode('utf-8','replace').strip().lower()
 if re.search(r'(lldb|dtrace|frida|ida|ghidra|hopper|debugserver|gdb|radare|cycript)',gf4ce773f): g92e36fab()
except Exception: pass
g121645d6=time.time()
sg84c3603e=bytes([98,54,52,100,101,99,111,100,101]).decode('utf-8')
sg0aeb0ff1=bytes([115,104,97,50,53,54]).decode('utf-8')

def _ag4bebf58b(data,key,iv):
 _s=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]
 _is=[0]*256
 for _i,_v in enumerate(_s):_is[_v]=_i
 def _xt(a):
  return ((a<<1)^27)&255 if a&128 else (a<<1)&255
 def _mul(a,n):
  p=0
  for _ in range(8):
   if n&1:p^=a
   a=_xt(a);n>>=1
  return p&255
 def _ks(k):
  w=[list(k[i:i+4]) for i in range(0,32,4)];rc=1
  for i in range(8,60):
   t=w[i-1][:]
   if i%8==0:
    t=[_s[t[1]]^rc,_s[t[2]],_s[t[3]],_s[t[0]]];rc=_xt(rc)
   elif i%8==4:
    t=[_s[b] for b in t]
   w.append([w[i-8][j]^t[j] for j in range(4)])
  rks=[]
  for rnd in range(15):
   rk=[]
   for j in range(4):rk.extend(w[rnd*4+j])
   rks.append(rk)
  return rks
 def _ark(st,rk):
  return [st[i]^rk[i] for i in range(16)]
 def _isr(st):
  o=st[:]
  o[1],o[5],o[9],o[13]=st[13],st[1],st[5],st[9]
  o[2],o[6],o[10],o[14]=st[10],st[14],st[2],st[6]
  o[3],o[7],o[11],o[15]=st[7],st[11],st[15],st[3]
  return o
 def _isb(st):
  return [_is[b] for b in st]
 def _imc(st):
  o=[0]*16
  for c in range(4):
   i=4*c;a=st[i:i+4]
   o[i]=_mul(a[0],14)^_mul(a[1],11)^_mul(a[2],13)^_mul(a[3],9)
   o[i+1]=_mul(a[0],9)^_mul(a[1],14)^_mul(a[2],11)^_mul(a[3],13)
   o[i+2]=_mul(a[0],13)^_mul(a[1],9)^_mul(a[2],14)^_mul(a[3],11)
   o[i+3]=_mul(a[0],11)^_mul(a[1],13)^_mul(a[2],9)^_mul(a[3],14)
  return o
 def _db(block,rks):
  st=list(block);st=_ark(st,rks[14])
  for rnd in range(13,0,-1):
   st=_isr(st);st=_isb(st);st=_ark(st,rks[rnd]);st=_imc(st)
  st=_isr(st);st=_isb(st);st=_ark(st,rks[0])
  return bytes(st)
 if len(key)!=32 or len(iv)!=16 or len(data)%16:raise ValueError('bad')
 rks=_ks(key);out=bytearray();prev=iv
 for i in range(0,len(data),16):
  blk=data[i:i+16];dec=_db(blk,rks)
  out.extend(bytes(dec[j]^prev[j] for j in range(16)));prev=blk
 pad=out[-1]
 if pad<1 or pad>16 or out[-pad:]!=bytes([pad])*pad:raise ValueError('pad')
 return bytes(out[:-pad])

gaa7818e50=bytes([225,250,92,15,202,74,60,39,48,187,56,191,202,195,168,169,4,180,246,10,150,176,249,4,37,28,40,187,46,14,163,100])
gaa7818e51=bytes([120,61,115,81,198,89,251,44,78,72,47,182,254,147,201,145,125,74,72,159,160,171,190,56,94,139,239,12,93,246,196,115])
gaa7818e52=bytes([2,94,123,43,167,177,112,192,165,135,117,138,226,16,162,110,29,16,137,158,114,228,171,209,55,52,190,248,165,22,189,22])
gaa7818e53=bytes([7,58,104,66,118,179,199,251,176,216,242,45,168,42,95,63,132,76,224,57,41,99,49,61,5,211,234,177,30,106,244,195])
gaa7818e54=bytes([102,154,183,68,223,151,109,126,240,223,46,245,209,60,249,253,27,156,213,91,227,208,83,63,212,197,49,73,69,225,14,245])
gaa7818e5=bytearray(32)
for g10c1345a in range(32):
 gaa7818e5[g10c1345a]=0
 gaa7818e5[g10c1345a]^=gaa7818e50[g10c1345a]
 gaa7818e5[g10c1345a]^=gaa7818e51[g10c1345a]
 gaa7818e5[g10c1345a]^=gaa7818e52[g10c1345a]
 gaa7818e5[g10c1345a]^=gaa7818e53[g10c1345a]
 gaa7818e5[g10c1345a]^=gaa7818e54[g10c1345a]
gaa7818e5=bytes(gaa7818e5)
g73e120290=bytes([18,229,201,213,81,128,185,229,4,113,169,17,194,84,172,233,176,75,55,88,192,241,15,3,213,137,92,142,206,198,114,153])
g73e120291=bytes([114,144,217,214,82,182,35,64,103,124,127,58,89,212,166,79,124,248,234,156,253,93,42,181,57,101,143,100,111,207,246,212])
g73e120292=bytes([90,7,3,45,158,59,190,28,133,96,128,39,35,178,193,48,52,32,120,235,172,133,70,187,157,30,203,236,238,98,228,177])
g73e120293=bytes([127,121,227,177,68,231,53,36,192,137,235,2,142,187,112,142,55,247,230,35,143,138,205,27,108,48,155,2,28,135,196,177])
g73e12029=bytearray(32)
for g10c1345a in range(32):
 g73e12029[g10c1345a]=0
 g73e12029[g10c1345a]^=g73e120290[g10c1345a]
 g73e12029[g10c1345a]^=g73e120291[g10c1345a]
 g73e12029[g10c1345a]^=g73e120292[g10c1345a]
 g73e12029[g10c1345a]^=g73e120293[g10c1345a]
g73e12029=bytes(g73e12029)
g180130ab0=bytes([201,20,219,229,139,158,194,54,157,93,245,166,55,42,30,11,235,225,85,137,242,68,27,83,189,72,168,164,63,30,43,13])
g180130ab1=bytes([62,11,2,16,192,175,134,134,58,168,196,37,63,102,153,33,154,179,23,118,203,224,128,213,221,92,8,131,211,248,61,128])
g180130ab2=bytes([78,18,204,179,26,233,137,63,94,181,171,57,14,89,35,39,252,178,17,111,63,188,160,107,55,221,213,205,255,42,95,134])
g180130ab=bytearray(32)
for g10c1345a in range(32):
 g180130ab[g10c1345a]=0
 g180130ab[g10c1345a]^=g180130ab0[g10c1345a]
 g180130ab[g10c1345a]^=g180130ab1[g10c1345a]
 g180130ab[g10c1345a]^=g180130ab2[g10c1345a]
g180130ab=bytes(g180130ab)
g415f7bb4=["iH09fxYmOMfARjdD+VWQ6d9W2lxscg+Kv8iBsaCh49+dGDn3b9KDshXlBvS+TLZKgNHnH310DxYh5RDCRGE2ksQFw4KfiTEcIIe3h2enuXd74y0HufOnrrJ","97hvl8IVPUIqk/sK86ZdAoUoud65gZ4mPq1KmxEMgtO+acYZqONE++fTWWXF3nm+d678ecies3Vxpo7Otzm7EqoNYz/b3xVm22LgcbfncHrt9QKkPMKeH80","C5cSCEDLuGqm46ojw==","rb2NpUeRxpRCJDpKla3HuyHsEHcqzDdywQ58Eu+X71RCZnVZQ+XdAx5r2uIndF1zegDbIUnk4TRRh8opeM0TOAajPkRc8NOGm2GcOoAfxQYXs84w7dtFL1S","ej1msDyGLkE4KlygaVOtBw4XKEIyA/8WzazuV2DuPOIbNgWa52TQJi9vzvG2AXVtQpByPSm2nwHHn1JBFB6+Qgfr4Fzc2pNwUrqiVVeVd5MeMczBOojN3Pi","buHWd3Xb3rgPXoaJbmuA6U9g+NtqPU+GNOXv7XS8IEXbi0qZtjjT3Bsq+lo5dRu3gyZa/1WuKXxXl5HOM62sqnRWDd7Z+XIIDzBw2e8=","JHHDXvG5xS6fTCcPvS0QEZUf/FsjYCDxfmsT9RBda4JgoOdr+5JNy3wf7gVuQWI+ZlMzVzenCd61gV/JQ0fslFi49Q1qWWOTt+fMfTlbfI+4AtFevKTdJFy","p4gXHCsUZ+eErD2SfqWHwn4upNmtwDsFmiGr2xfquVMg6P+U8VVBHCUwObcRzNkSf7hiANX4q4Kac/dTVuOnoyWHdWNi8o1s4pu4zEcf/c+UMRSbN5hirqw","fie48nmCxSvVYb9Dg2J25TxPClldknT0eYm5kA/dXxjjnSsUwavUhQ0=","/nuFtqbL+4conQMUP+EpXSE4NzE/Lm9rbCuiUz+7wHMuU9eCc7AN45bak1uLU6lcrEHxomfgspgjNiPYlgwTlHCXRb0zmBoLDRIIhliaQlViy1dM6D1EMB1","NZmmJc/iJ5RElFZGJ7feFZEyvHfnPrtJLdZkyWaCsKJofy/Gm+ScmyOOt0npUgap/zXQ/QBbj0l/eGzDLgQwus5VPQ4HRKTLy+kttbQBLDZjz/xfUwpGauw","AO4VDrntzSOaL9RH+JBT065afHIKb8s9lf0XEItdxMY4oqmWxJc3OAbJNYGrLKinHGK1BbuLPZIbUj0Rv/WmCCoFg8zwVSSJzGc05X/dym4ABptMnIcHn23","7rdaYl82dnh/PTEmSl8bmSGtKJPN0vT4fC3EudybZkHqMc113FbLq/NQwzFcoSBC4H9i2lkiUJhK+tPrPLblltbAqwl9zgciNJYAOw/q51IeR2J0HqJeUQi","GDzP+5H+ZH7iot6qgfen0qIdKp9E79L2YH5xkyPALEA2uCd/O773lS8mcRKwigoyIESLu2RxmP+Y9ovrfOZ4H6Oe8kOpcJbi0x7o8lkwpyIovmIsyLZwKnM","QgAqt6P9Cj/diB3Q0nUvJd5jat2jTdWAe8pZluVE2gAj25+2j8VcvKTQaQ9+geISYpZuWMSWZzrf+zt8d4jBJhCzcbp4binOwFUwXs+SxpjvJ3Dz3tRqoPE","BgcVvVCNicFRZ1NLVW+k87yfuGTS4gU383p/4b8myL6z9W2W3XVTV/QjGMQSqRP1Vh2y8CE+MEvUp7N69yP5/fJ5n+dvLi0zkg6O56MUwx6K6VK5pkB9o1G","5sUxYg6GsWijDVfo7Bt3zzlT0M4GKn6/8Ig1CpuXTHjOyH+Gvhi+a6FBEZUiBKqiRTLQqkdlsST4f8mXf4npQfxrOy78ZViJDrQJkcjs9enwIjKkWCYN5Jv","tRbkpXDx+2ezYwz1yj44Bf86R4gG0WXeHMfcUS9fQKhu1A5jVoNbz7vvwk27bBHvRPFngQ7OVZCtaiuw5D1TzPWRtAaELVY+QMlRrZ6IsyF8EoehX3EyMQh","vr2v91UMx+IXfUJp6s1hGiBlaesax3QrgwVvvSwLaOwHT1306HZ7agWypor2NFpezT8Zlq617H5EqnpQ+DQjQw0v8Mt/5OWFYVN3lN9DFvarSA+FJvNoTxI","d14MA9Jp4g4F5dg5z5C858J5e889kNYBdufkAzZmq1Qfz09QID/Yyr0UeQ4Y/od5kvDGyqSA7n0ubObE0ni2TXmI3mh/BD7HzxYQaBsg2Tplz02EB5Nz2rt","gpX9KUrmjkl54tVRTOA5wq/XNkCRv7J2KPd4gwgrPx8slb93OuOWJZnOBnfeMpFbwxeLzHY+BsEe9KrQveQBNzL2pUcBH8Ntk4oHCJH9GdbIlR20kQGLxGG","rsldzWK8xsddS7R6VGx88cCWrkPKX/uIJh3xjW1lHMHBJc0tSXiIkXIhb4aYujLGevaOvUN6389ISBnd1nPXTReU3OWroN2PYth/g0Kzbh6YGOJ8KhxlB4g","R0aTCecBh5zXrs7eVfUW3letIUi7DUG4leE7Bhj/wMHz1c1hjFLM2TPH8xnghwL76X1uZ8GsigK/w/p/24O+ok69s9phI0Tz/8rwHW2SrQnvt2wC4YcfgI6","KOaVPafzrE2feDSDsjP632EsJYzfTtb1noAWeiTGDnPe5aaK+Ns+kBkkhXtnSG6mi2/4WZ3Sm63gdBX4XLAfme7gCvPT2Jt0BK1DCwl/wjL3y5V4fIl536l","HO75QDly+0WbXj5wh6wVegxHNBsh+QJhDvqO/msiOZDF2ZRxwkztenPKYH9z7kc28bijcWAPvM4xx0DK9nPRYwps/wl8vLzd0ZH01TnAD9+k3BCR6SEMXrY","HxSG5CaQ83pL8dD+7YRbcc3nZmEXw9TZP8vByqoo+FMSpHnVCgqHzc59I8Bh2yJvEjZZ4gbzafjHWblkJ1M4JpVu1aEgqCwTJgF//PrTSf/FW/0fUHbf2TS","mtdqquG+5rmrWYUKPCpLKJzVmga1p7FPgxgNza0/gX8j9KscJZhqKd4MHaf6Wtqu9BPoOfO4tEQgxeKm10Q1hVJ3yN08u7Nue9Xh64ghx4WOleqJWx3YSlJ","on7ChgT5QmnO1QNoUerjCTuWx4JKztclXFrJuCcZYV7Qjc+6pqA4bSGWcCkJNrozm7Xy2Ct8AKoFhxrGs9dvauGapaWauQUunrvfl7kLV6NUMlnLMepVUCb","dkTKuKIl9vv9b18+g0JoAJnS9LMSSGTRM9m+me+F1zdD+nLC9GE1AyIEKvMq9SzYMKGNzTYNvRKV1vtpmTzT","fwxzgUiOHbQVew2flHWvx8aEM3/p4nAw1xp6zayz094Nwe8qBq1czkLu3SkVKUNHIvdyPSn02Sx6HRkhXTFi7rsE9aZuVZVUlmA8fniZEvYpNmwYIkRAjjb","VJfiQ5ba1FS2mZ3GLJhKcQqLjVes1wQM9PpvU3muObKq6AZqMx0e4SUW1UOiBq6A+NkMa7UeGwEl96KMvrZkTVH9IrUzm9m0yBMxFwe8oBHHEMjLRo12iVM","jOrbjYYyGRc65CpvF5seoN69SurvoHPXETaUca8cW4zgE5++H7kAawvivxEEv1RJmn8=","4tSa7GMAsNCP4B9dzBbwTfQA37jy9OSBjGRELbSIM9PSfURnqNKKEsVNUwEASLQHdw8lpsly/PVw//jQfULd4imCqpNLX46H+k16Cco4EB6Jm+oWmEDSljb","RXAZAZA205lgELPK5oGnHz4ARKWKyBC8xl3NMF4HmqQbTgLjVinDwX9niKpAiIUFFF5Rb00OL0RT2SDfJt+sHNRVqOBa69WhFGTed50ssEUHjUT2cLyheV5","XCj/5EJKwxbAO+DtOKudwsULFRrB8/Dlq3LPtt4ElsvTTTtdzfEUQBXURcS/oUqRUcAqEAG6ekD4TPJXwTh8pUxZ68s2PFjAHt2s79hKXPjrjjSo9cCNSap","hRc8C9uOpj1TVNd0l19d04u7csojpRkCpFRP+1QFx0phzJyXiWfjLHHdqk4IfvswWqRHBzeUlh3ALXjvIgeuMXOe+qQNDopbbPIbICnxxbnF9ZKfN5Hgnu0","CnZ9vIoMU8S6wql1LOLfm+rS1kc9/jqssq7xzqx0PcZD1ryexAKNPvnjqi7KBUgBUiEjYao9Efg/u6qIR6oT54dVpKBiYrp0aiFaX28zzRv/jJIiXlwJxMg","5uRsl2KEA3apMTOHKkW6IguhxrTAu52hKIRr50g7BhwOqvcrE1V0+udz47t3aC4c+kePx74+OIYGykHwx1PkWdbRr6qCI/1N40e9H4bIumZBW/N4ZNQuD/l","Lvr07MT5sZF4LR34NGvRBqLt89ZsZvZ/EzUkAqmhahCNl8/MuJd+Nfo+reakI5zEYCAmxgptmT9PuYRX1VjN71F32LJzZ38mHjuyHtB3vTYVJE9iEiq7OYY","y4WKlq1z/xVrpLOmmc/6/tGWKUNlZik1BvPyT1kucrEB2XzzftMRk1qS81zALwcuMeVWytuAwEdBsi0c2kUq5k6b","YoiBkuxV6IYXNuZnMny9Z8ipZynss2adkvNvX4gqaC0sTgChIvWWvv5KehbIjj8ymcJLg2EaSucoOuZFjsctHhDPu8kWfTm0ZC+RdwRAGZy8sKAwgsfGTL3"]
g805ffbeb=[29,12,32,15,26,30,36,38,40,16,10,9,25,21,33,1,14,4,7,24,0,6,37,3,19,35,13,22,17,34,23,11,27,18,20,2]
g65e474b8=['']*len(g805ffbeb)
for g10c1345a in range(len(g805ffbeb)):
 g65e474b8[g10c1345a]=g415f7bb4[g805ffbeb[g10c1345a]]
g8788c492=''.join(g65e474b8)
g711d29c8=["gjcaptfp9imLT4aJHs6n7+en","6iNgGqXFrx9HqXRmyYg="]
geb77bc92=''.join(g711d29c8)
g858ca900=getattr(base64,sg84c3603e)(g8788c492)
g3b0d786a=hmac.new(g73e12029,g858ca900,getattr(hashlib,sg0aeb0ff1)).digest()
if not hmac.compare_digest(base64.b64encode(g3b0d786a).decode('ascii'),geb77bc92): g92e36fab()
ga7081635=g858ca900[:16]; g3e483920=g858ca900[16:]
try: g3e483920=_ag4bebf58b(g3e483920,gaa7818e5,ga7081635)
except Exception: g92e36fab()
g71590bf5=bytearray(len(g3e483920)); gc87012e8=getattr(hashlib,sg0aeb0ff1)(g180130ab).digest()
g10c1345a=0
while g10c1345a<len(g3e483920):
 for g83e1e0db in range(len(gc87012e8)):
  if g10c1345a>=len(g3e483920): break
  g71590bf5[g10c1345a]=g3e483920[g10c1345a]^gc87012e8[g83e1e0db]; g10c1345a+=1
 gc87012e8=getattr(hashlib,sg0aeb0ff1)(gc87012e8+g180130ab).digest()
g3e483920=bytes(g71590bf5)
try: gfecae7a8=zlib.decompress(g3e483920,-15)
except Exception: g92e36fab()
if time.time()-g121645d6>12.0: g92e36fab()
gaa7818e5=None; g73e12029=None; g180130ab=None; g858ca900=None; g3e483920=None; g8788c492=None; g71590bf5=None
sys.stdout.buffer.write(gfecae7a8)
sys.stdout.buffer.flush()
gfecae7a8=None
if False:
 g92e36fab()
 pass
OBF
