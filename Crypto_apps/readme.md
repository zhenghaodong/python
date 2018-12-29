# 简介

基于D-H协议，双方互相通信

## 支持算法

* RSA
* LFSR+JK触发器
* RC4
* AES
* DES
* 仿射

## 工作流程

* A,B通信双方约定好大素数以及其对应的原根，各自选取一个随机数i,j,利用公式算出Sa = a^i mod p,Sb = a^j mod p,利用socket通信交换Sa、Sb
* 接收到对方的Sa、Sb之后，得到公有的私钥S = Sa^j = Sb^i
* A选取要加密的text以及对应的加密算法,利用加密算法加密出cipher
* 为了防止中间人攻击,利用RSA在cipher被hash算法(md5或sha)散列之后的string上签名(签名的公钥、私钥双方协定好)得到Ecipher
* A将最终的字符串SEND(cipher+Ecipher)发送给B
* B拿到SEND之后,先将Ecipher提取出来,用约定好的私钥解开签名得到散列X,将X与hash(cipher)比较,若相等,证明没遭遇中间人攻击
* B用之前算好的S解密cipher,得到text

## 工作

不写前端，只负责算法,由于通信方面涉及到类型的问题,感谢队友帮我把加密解密出来的字符类型统一
