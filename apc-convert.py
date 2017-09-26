
import json
import sys
import argparse
import os.path
from Crypto.PublicKey import RSA

CERT_START = "-----BEGIN CERTIFICATE-----"
CERT_END   = "-----END CERTIFICATE-----"

RSA_START  = "-----BEGIN RSA PRIVATE KEY-----"
RSA_END    = "-----END RSA PRIVATE KEY-----"

# Python 2.x Workaround
if hasattr(__builtins__, 'raw_input'):
   input=raw_input

class OVPNFile(object):
   def __init__(self):
      self.content = {"client": [], "dev": ["tun"], "resolv-retry": ["infinite"], "auth": ["SHA256"]}
      self.login = None


   @property
   def cert(self):
      cert = self.content.get("cert", [""])[0]
      if "\n" in cert:
        return cert
      
      if os.path.exists(cert):
         cert_file = open(cert, "r")
         head_found = False
         for line in cert_file: #Seek Cert file until relevant content
            if line.find(CERT_START) >= 0:
               cert = line[line.find(CERT_START):]
               head_found = True
            elif head_found:
               cert += line
         cert_file.close()
         cert = cert.strip()
      
      return cert

   @cert.setter
   def cert(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(CERT_START): raise ValueError()
      self.content['cert'] = [value]

   @property
   def key(self):
      cert = self.content.get("key", [""])[0]
      if "\n" in cert:
        return cert
      
      if os.path.exists(cert):
        return open(cert, "r").read()
      
      return cert

   @key.setter
   def key(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(RSA_START): raise ValueError()
      self.content['key'] = [value]

   @property
   def ca(self):
      cert = self.content.get("ca", [""])[0]
      if "\n" in cert:
        return cert
      
      if os.path.exists(cert):
        return open(cert, "r").read()
      
      return cert

   @ca.setter
   def ca(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(CERT_START): raise ValueError()
      self.content['ca'] = [value]


   @property
   def proto(self):
      return self.content.get("proto", [""])[0]

   @proto.setter
   def proto(self, value):
      if value.lower() not in ("tcp", "udp", "tcp6", "udp6"): raise ValueError()
      self.content["proto"] = [value.lower()]

   @property
   def remote(self): return self.content.get("remote", [""])

   @remote.setter
   def remote(self, value): self.content["remote"] = value

   @property
   def remote_cert_tls(self): return self.content.get("remote-cert-tls", [""])[0]

   @remote_cert_tls.setter
   def remote_cert_tls(self, value): self.content["remote-cert-tls"] = [value]
 
   @property
   def cipher(self): return self.content.get("cipher", [""])[0]

   @cipher.setter
   def cipher(self, value): self.content["cipher"] = [value]
   
   @property
   def auth(self): return self.content.get("auth", [""])[0]

   auth.setter
   def auth(self, value): self.content["auth"] = [value]

   @property
   def comp_lzo(self):
      return "comp-lzo" in self.content

   @comp_lzo.setter
   def comp_lzo(self, value):
      if value:
         self.content["comp-lzo"] = []

   def getLogin(self):
      try:
         self.content["auth-user-pass"].remove("")
         userPass = open(self.content["auth-user-pass"][0])
         return userPass.readline().strip(), userPass.readline().strip()
      except:
         return None, None

   def addLogin(self, username, password):
      self.content["auth-user-pass"] = ["login.txt"]
      self.login = username + "\n" + password

   def _parseLine(self, line):
      line = line.strip()
      if len(line)==0 or line[0] in ("#", ";"): return
      line = line.split(" ")
      key = line[0]
      val = " ".join(line[1:])
      
      values = self.content.get(key, [])
      values.append(val)
      self.content[key] = list(set(values))


   def load(self, filestream):
      self.__init__()
      try:
        for line in filestream:
            self._parseLine(line)
      except StopIteration:
        pass

   def save(self, filestream):
      txtCont = ""
      
      for key in self.content:
        val = self.content[key]
        if len(val) == 0: val=[""]
        
        for v in val:
           if isinstance(v, list):
              v = " ".join(v)
            
           if "\n" in v or len(v)>300:
              txtCont += "\n<"+ key + ">\n" + v + "\n</" + key + ">\n\n"
           else:
              txtCont += key + " " + v + "\n"
      filestream.write(txtCont)
      
      if "auth-user-pass" in self.content:
         open(self.content["auth-user-pass"][0], "w").write(self.login)

class APCFile(object):
   def __init__(self):
      self.content = {
                      "key":"",
                      "protocol":"tcp",
                      "server_port":"",
                      "certificate":"",
                      "ca_cert":"",
                      "server_dn":"",
                      "server_address":[""],
                      "authentication_algorithm":"SHA256",
                      "username":"",
                      "encryption_algorithm":"BF-CBC",
                      "compression":"",
                      "password":""
                      }

   @property
   def cert(self):
      return self.content.get("certificate")

   @cert.setter
   def cert(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(CERT_START): raise ValueError()
      
      if not value.startswith(CERT_START + "\n"):
        value = value.replace(CERT_START, CERT_START + "\n")
      
      if not value.endswith("\n" + CERT_END):
        value = value.replace(CERT_END, "\n" + CERT_END)
      
      self.content['certificate'] = value

   @property
   def key(self):
      return self.content.get("key")

   @key.setter
   def key(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(RSA_START): raise ValueError()
    
    
      if not value.startswith(RSA_START + "\n"):
        value = value.replace(RSA_START, RSA_START + "\n")
        
      if not value.endswith("\n" + RSA_END):
        value = value.replace(RSA_END, "\n" + RSA_END)
      self.content['key'] = value

   @property
   def ca(self):
      return self.content.get("ca_cert")

   @ca.setter
   def ca(self, value):
      value = value.replace("\n", "").strip()
      if not value.startswith(CERT_START): raise ValueError()
      
      if not value.startswith(CERT_START + "\n"):
        value = value.replace(CERT_START, CERT_START + "\n")
      
      if not value.endswith("\n" + CERT_END):
        value = value.replace(CERT_END, "\n" + CERT_END)
      
      self.content['ca_cert'] = value


   @property
   def proto(self):
      return self.content.get("protocol")

   @proto.setter
   def proto(self, value):
      if value.lower() not in ("tcp", "udp", "tcp6", "udp6"): raise ValueError()
      self.content["protocol"] = value.lower()


   @property
   def username(self): return self.content.get("username")

   @username.setter
   def username(self, value): self.content["username"] = value
 
   @property
   def password(self): return self.content.get("password")

   @password.setter
   def password(self, value): self.content["password"] = value
 
   @property
   def remote_cert_tls(self): return self.content.get("server_dn")

   @remote_cert_tls.setter
   def remote_cert_tls(self, value): self.content["server_dn"] = value
 
   @property
   def cipher(self): return self.content.get("encryption_algorithm")

   @cipher.setter
   def cipher(self, value): self.content["encryption_algorithm"] = value
   
   @property
   def auth(self): return self.content.get("authentication_algorithm")

   auth.setter
   def auth(self, value): self.content["authentication_algorithm"] = value

   @property
   def remote(self):
      outp = []
      for r in self.content.get("server_address"):
         outp.append(r + " " + self.content.get("server_port"))
      return outp

   @remote.setter
   def remote(self, value):
      try:
         self.content["server_address"] = []
         for v in value:
            server, port = v.split(" ")
            if self.content.get("server_port") == "":
               self.content["server_port"] = port
            if self.content["server_port"] != port:
               raise ValueError("Different ports per remote isn't supported with apc")
            self.content["server_address"].append(server)
      except:
         raise ValueError()

   @property
   def comp_lzo(self):
      return self.content.get("compression") == ""

   @comp_lzo.setter
   def comp_lzo(self, value):
      try:
         self.content["compression"] = str(int(value))
      except:
         raise ValueError()

   def save(self, filestream):
      jcontent = json.dumps(self.content, separators=(',',':')).replace("\n", "")
      filestream.write(jcontent)

   def load(self, filestream):
      jcontent = ""
      try:
        for line in filestream:
            jcontent+=line
      except StopIteration:
        pass
      self.content = json.loads(jcontent)

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description='converts ovpn and cert files to sophos apc and reverse')
   
   parser.add_argument('action', metavar='action', type=str, help='ovpn2apc or apc2ovpn')
   parser.add_argument('src', metavar='src', type=argparse.FileType('r'), help='input apc/ovpn file "-" for stdin')
   parser.add_argument('dst', metavar='dst', type=argparse.FileType('w'), help='output apc/ovpn file "-" for stout')
   parser.add_argument('--username', metavar='user', type=str, nargs='?', help='vpn username, only if action is ovpn2apc')
   parser.add_argument('--password', metavar='pwd', type=str, nargs='?', help='vpn password, only if action is ovpn2apc')
   
   args = parser.parse_args()
   
   apc = APCFile()
   ovpn = OVPNFile()
   
   if args.action == "ovpn2apc":
      ovpn.load(args.src)
      
      
      username = args.username
      password = args.password
      
      if username is None and password is None:
         username, password = ovpn.getLogin()
      
      if username is None:
         username = input("Please enter VPN User: ")
      
      if password is None:
         import getpass
         password = getpass.getpass("Please enter VPN Password: ")

      apc.ca = ovpn.ca
      apc.username = username
      apc.password = password
      apc.cipher = ovpn.cipher
      apc.auth = ovpn.auth
      apc.comp_lzo = ovpn.comp_lzo
      apc.proto = ovpn.proto
      apc.remote = ovpn.remote
      apc.remote_cert_tls = ovpn.remote_cert_tls
      
      try:
         apc.cert = ovpn.cert
      except ValueError:
         # Convert key to RSA
         key = RSA.importKey(ovpn.cert)
         apc.cert = key.exportKey().decode()
      
      try:
         apc.key = ovpn.key
      except ValueError:
         # Convert key to RSA
         key = RSA.importKey(ovpn.key)
         apc.key = key.exportKey().decode()

      apc.save(args.dst)
      
   elif args.action == "apc2ovpn":
      apc.load(args.src)      
      ovpn.cert     = apc.cert
      ovpn.ca       = apc.ca
      ovpn.key       = apc.key
      ovpn.cipher   = apc.cipher
      ovpn.auth     = apc.auth
      ovpn.comp_lzo = apc.comp_lzo
      ovpn.proto    = apc.proto
      ovpn.remote   = apc.remote
      ovpn.remote_cert_tls = apc.remote_cert_tls
      ovpn.addLogin(apc.username, apc.password)
      
      ovpn.save(args.dst)
   else:
      print("unknown action '"+args.action+"'\n")
      parser.print_help()
