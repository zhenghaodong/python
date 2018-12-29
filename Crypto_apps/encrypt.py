from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import cgitb, sys, time
from binascii import a2b_hex,b2a_hex
import Global_Var, algorithm
import hashlib
import getpass
from Crypto import Random
from socket import *

# 导入QT资源
import UI.qrcPath

# 初始化全局变量

global global_iv,global_LF1,global_LF2
global rsaobj, myrsaPubPriobj, opporsaPubK

Global_Var._init()

# 让程序报错正常
cgitb.enable( format = 'text')

Ui_MainWindow, QtbaseClass_0 = uic.loadUiType("./UI/Main.ui")

# 加密算法及密钥配置列表
encryptAlgorithm = ['仿射加密', '流密码加密', '对称加密', '非对称加密']
comboBox_AlgorithmConf = [['None'], ['RC4', 'LFSR+J-K触发器'], ['DES', 'AES'], ['RSA']]
KeyConfList = [[['参数a', '参数b']],
               [['流密码RC4-a', '流密码RC4-b'], ['流密码LFSR-a']],
               [['对称加密DES-a', '对称加密DES-b'], ['对称加密AES-a', '对称加密AES-b']],
               [['非对称加密a', '非对称加密b']]]

class Main(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.setWindowTitle('加密解密')

        #接收发送线程
        self.Recv_Thread = RecvData()
        self.Send_Thread = SendData()

        # 加密按键相关线程连接
        self.pushButton_Encrypt.clicked.connect(self.encryptclicked)
        self.encrypt_Thread = encryptOperate()
        self.encrypt_Thread.encryptThread.connect(self.displayEncrypt)

        # 解密按键相关线程连接
        self.pushButton_Decrypt.clicked.connect(self.decryptclicked)
        self.decrypt_Thread = decryptOperate()
        self.decrypt_Thread.decryptThread.connect(self.displaydecrypt)

        # 设置算法下拉列表变化连接
        self.comboBox_Algorithm.currentIndexChanged.connect(self.AlgorithmChange)
        self.comboBox_AlgorithmConf.currentIndexChanged.connect(self.AlgorithmConfChange)

        # 设置密钥配置变化连接
        self.textEdit_KeyConf.textChanged.connect(self.KeyConfChange)

        # 设置密钥配置预显示提示信息
        self.textEdit_KeyConf.setPlaceholderText('请输入初始秘钥，如有多个则每行输入一个，以便读取')
        self.textEdit_Plaintext.setPlaceholderText('请输入要加密的密文')
        self.textEdit_Ciphertext.setPlaceholderText('请输入要解密的密文')
        self.textEdit_OperateInfo.setPlaceholderText('加解密提示信息将在这里显示')

        # 初始化下拉列表
        self.comboBox_Algorithm.addItems(encryptAlgorithm)
        self.comboBox_Algorithm.setCurrentIndex(0)
        self.comboBox_AlgorithmConf.clear()
        self.comboBox_AlgorithmConf.addItem(comboBox_AlgorithmConf[0][0])

        #IP查询端口设置按键链接
        self.pushButton_GETIP.clicked.connect(self.GetIPclicked)
        self.pushButton_SetPort.clicked.connect(self.setportclicked)

        #发送公钥/密钥交换按钮配置线程连接
        self.pushButton_SendPk.clicked.connect(self.sendpkclicked)
        self.Send_Thread.sendThread.connect(self.displayinfo)
        self.Recv_Thread.recvThread1.connect(self.displayRPubKey)

        self.pushButton_ExchangeKey.clicked.connect(self.sendkeyclicked)
        self.Recv_Thread.recvThread2.connect(self.displayRKey)

        self.pushButton_calKey.clicked.connect(self.calkeyclicked)
        self.pushButton_SendData.clicked.connect(self.senddataclicked)
        self.Recv_Thread.recvThread3.connect(self.displayMsg)

    # 加密按钮被按下，设置全局变量进入线程
    def encryptclicked(self):
        # 获取明文的内容
        plainText = self.textEdit_Plaintext.toPlainText().encode("utf-8")
        # 获取密钥配置及明文，同时设置相关内容全局变量
        Global_Var.Set_value('comboBox_Algorithm', str(self.comboBox_Algorithm.currentIndex()))
        Global_Var.Set_value('comboBox_AlgorithmConf', str(self.comboBox_AlgorithmConf.currentIndex()))
        #Global_Var.Set_value('KeyConf', str(self.textEdit_KeyConf.toPlainText()))
        Global_Var.Set_value('plainText', plainText)
        self.textEdit_Plainhex.setText(str(b2a_hex(plainText)).upper()[2:-1])
        # 开启加密线程
        self.encrypt_Thread.start()

    # 解密按钮被按下，设置全局变量进入线程
    def decryptclicked(self):
        # 获取密文的内容
        ciphertext = self.textEdit_Ciphertext.toPlainText()

        # 获取密钥配置及密文，同时设置相关内容全局变量
        Global_Var.Set_value('comboBox_Algorithm', str(self.comboBox_Algorithm.currentIndex()))
        if int(Global_Var.Get_value('comboBox_Algorithm')) != 0:        
            ciphertext = a2b_hex(ciphertext)
        else:
            ciphertext = ciphertext.encode('utf-8')
        Global_Var.Set_value('comboBox_AlgorithmConf', str(self.comboBox_AlgorithmConf.currentIndex()))
        Global_Var.Set_value('ciphertext', ciphertext)

        # 开启解密线程
        self.decrypt_Thread.start()

    #IP查询
    def GetIPclicked(self):
        myIpAddr = gethostbyname(getfqdn(gethostname()))
        self.lineEdit_yourIP.setText(myIpAddr)

    #发送公钥按钮被按下
    def sendpkclicked(self):
        global myrsaPubPriobj
        ip = self.lineEdit_IP.text()
        port = self.lineEdit_PORT.text()
        Global_Var.Set_value('ip',ip)
        Global_Var.Set_value('port',port)
        myrsaPubPriobj = algorithm.rsa_crypto()
        msg = ('[#1]'+str(myrsaPubPriobj.pubkey))
        Global_Var.Set_value('sedata',msg)
        self.Send_Thread.start()

    #设置端口按钮
    def setportclicked(self):
        yPort = self.lineEdit_YPORT.text()
        if yPort == '':
            yPort = 8080
        try:
            if self.Recv_Thread.bindd(int(yPort)) == True:
                self.textEdit_OperateInfo.setText('端口设置成功，开始监听.\n')
                self.Recv_Thread.start()

        except ValueError:
            print('Error')

    #密钥交换按钮被按下
    def sendkeyclicked(self):
        global opporsaPubK
        ip = self.lineEdit_IP.text()
        port = self.lineEdit_PORT.text()
        keysend = self.lineEdit_Key.text()
        Global_Var.Set_value('ip',ip)
        Global_Var.Set_value('port',port)
        WillSend = '[#2]ChangeKey'+algorithm.HASH(keysend,opporsaPubK)
        Global_Var.Set_value('sedata',WillSend)
        self.Send_Thread.start()
        self.textEdit_SendKey.setText(str(algorithm.bytes2int(keysend.encode('utf-8'))))

    #计算共享密钥
    def calkeyclicked(self):
        myk = int(self.textEdit_SendKey.toPlainText())
        oppok = int(self.textEdit_RecvKey.toPlainText())
        sissk = algorithm.calk(myk,oppok)
        self.textEdit_Pbkey.setText(str(sissk))
        self.textEdit_OperateInfo.setText('计算共享密钥结果:\n'+str(sissk))
        Global_Var.Set_value('PbKey',sissk)

    #发送消息
    def senddataclicked(self):
        msg = self.textEdit_SendMsg.toPlainText()
        if len(msg) == 0:
            return
        Global_Var.Set_value('sedata',msg)
        self.Send_Thread.start()
        self.textEdit_SendMsg.setText('')

    # 算法选择变化
    def AlgorithmChange(self):
        selectedIndex = self.comboBox_Algorithm.currentIndex()
        self.comboBox_AlgorithmConf.clear()
        self.comboBox_AlgorithmConf.addItems(comboBox_AlgorithmConf[selectedIndex])

    # 算法二级菜单变化，暂时没用
    def AlgorithmConfChange(self):
        pass

    # 密钥配置变化后的处理
    def KeyConfChange(self):
        tmpk = self.textEdit_KeyConf.toPlainText().encode("utf-8")
        Global_Var.Set_value('KeyConf',tmpk)
        self.textEdit_KeyConfhex.setText(str(b2a_hex(tmpk)).upper()[2:-1])

    # 加密按钮被按下后线程返回显示前面板
    def displayEncrypt(self, strres, strinfo):
        self.textEdit_Ciphertext.setText(strres)
        self.textEdit_OperateInfo.setText(strinfo)

    # 解密按钮被按下后线程返回显示前面板
    def displaydecrypt(self, strres, strres2, strinfo):
        self.textEdit_Plainhex.setText(strres2)
        self.textEdit_Plaintext.setText(strres)
        self.textEdit_OperateInfo.setText(strinfo)

    #发送信息后返回显示前面板
    def displayinfo(self,strinfo):
        self.textEdit_OperateInfo.setText(strinfo)

    #得到公钥后返回显示前面板
    def displayRPubKey(self,strres,strinfo):
        self.textEdit_OperateInfo.setText(strinfo)
        self.lineEdit_otherPK.setText(strres)

    #得到对方传送密钥后返回显示前面板
    def displayRKey(self,strres,strinfo):
        self.textEdit_OperateInfo.setText(strinfo)
        self.textEdit_RecvKey.setText(strres)

    #得到消息后返回显示前面板
    def displayMsg(self,strres):
        self.textEdit_RecvMsg.setText(strres)

    # 关闭界面
    def close(self):
        window.close()

# 加密线程
class encryptOperate(QThread):
    encryptThread = pyqtSignal(str, str)
    def __init__(self, parent = None):
        super(encryptOperate, self).__init__(parent)

    def run(self):
        #一级菜单选择选项
        Algorithm = int(Global_Var.Get_value('comboBox_Algorithm'))
        #二级菜单选择选项
        AlgorithmConf = int(Global_Var.Get_value('comboBox_AlgorithmConf'))
        #秘钥配置框内容
        KeyConf = Global_Var.Get_value('KeyConf')
        #明文框内容
        plainText = Global_Var.Get_value('plainText')

        #具体加密过程

        #仿射加密
        if Algorithm == 0:
            # 把密钥分割的代码放到加密算法里面去，这里就只输入密钥就好了
            r = algorithm.Radiate()
            result = r.encryption(plainText, KeyConf)
        #流密码加密
        elif Algorithm == 1:
            #RC4
            if AlgorithmConf == 0:
                r = algorithm.RC4(KeyConf)
                result = r.do_crypt(plainText)
                result = str(b2a_hex(result)).upper()[2:-1]
            #LFSR+J-K触发器
            elif AlgorithmConf == 1:
                r = algorithm.crypto_LFSR(KeyConf,global_LF1,global_LF2)
                result = r.do_crypt(plainText)
                result = str(b2a_hex(result)).upper()[2:-1]
        #对称加密
        elif Algorithm == 2:
            #DES
            if AlgorithmConf == 0:
                r = algorithm.des_crypto(KeyConf, global_iv)
                result = r.encrypt(plainText)
                result = str(b2a_hex(result)).upper()[2:-1]
            #AES
            elif AlgorithmConf == 1:
                r = algorithm.aes_crypto(KeyConf)
                result = r.encrypt(plainText)
                result = str(b2a_hex(result)).upper()[2:-1]
        #非对称加密 RSA
        elif Algorithm == 3:
            global rsaobj
            KeyConf = b'Random'
            result = rsaobj.rsa_encrypt(plainText)
            result = str(b2a_hex(result)).upper()[2:-1]

        #其他异常情况
        else:
            result = 'Error'
        self.encryptThread.emit(result,
                                '加密线程已启动' + '\n'
                                + '算法选择：' + encryptAlgorithm[Algorithm] + ' '
                                + comboBox_AlgorithmConf[Algorithm][AlgorithmConf] + '\n'
                                + '密钥配置：' + KeyConf.decode('utf-8') + '\n'
                                + '明文为：' + plainText.decode('utf-8') + '\n'
                                + '结果为：' + result
                                )

# 解密线程
class decryptOperate(QThread):
    decryptThread = pyqtSignal(str, str,str)
    def __init__(self, parent = None):
        super(decryptOperate, self).__init__(parent)

    def run(self):
        #一级菜单选择内容
        Algorithm = int(Global_Var.Get_value('comboBox_Algorithm'))
        #二级菜单选择内容
        AlgorithmConf = int(Global_Var.Get_value('comboBox_AlgorithmConf'))
        #秘钥配置框内容
        KeyConf = Global_Var.Get_value('KeyConf')
        #密文框内容
        ciphertext = Global_Var.Get_value('ciphertext')
        
        #仿射解密
        if Algorithm == 0:
            # 把密钥分割的代码放到加密算法里面去，这里就只输入密钥就好了
            r = algorithm.Radiate();
            result2,result1 = r.decryption(ciphertext, KeyConf),'None'
        #流密码解密
        elif Algorithm == 1:
            #RC4
            if AlgorithmConf == 0:
                r = algorithm.RC4(KeyConf)
                result = r.do_crypt(ciphertext)
                result1 = 'None'
                result2 = result.decode('utf-8','ignore')
            #LFSR+J-K触发器
            elif AlgorithmConf == 1:
                r = algorithm.crypto_LFSR(KeyConf,global_LF1,global_LF2)
                result= r.do_crypt(ciphertext)
                result1 = str(b2a_hex(result)).upper()[2:-1]
                result2 = result.decode('utf-8','ignore')
        #对称解密
        elif Algorithm == 2:
            #DES
            if AlgorithmConf == 0:
                r = algorithm.des_crypto(KeyConf, global_iv)
                result = r.decrypt(ciphertext)
                result1 = str(b2a_hex(result)).upper()[2:-1]
                result2 = result.decode('utf-8','ignore')
            #AES
            elif AlgorithmConf == 1:
                r = algorithm.aes_crypto(KeyConf)
                result = r.decrypt(ciphertext)
                result1 = str(b2a_hex(result)).upper()[2:-1]
                result2 = result.decode('utf-8','ignore')
        #非对称解密 RSA
        elif Algorithm == 3:
            global rsaobj
            KeyConf = b'Random'
            result = rsaobj.rsa_decrypt(ciphertext)
            result1 = str(b2a_hex(result)).upper()[2:-1]
            result2 = result.decode('utf-8','ignore')
        #其他异常情况
        else:
            result2 = 'Error'
        self.decryptThread.emit(result2,result1,
                                '解密线程已启动' + '\n'
                                + '算法选择：' + encryptAlgorithm[Algorithm] + ' '
                                + comboBox_AlgorithmConf[Algorithm][AlgorithmConf] + '\n'
                                + '密钥配置：' + KeyConf.decode('utf-8') + '\n'
                                + '明文为：' + result2
                                )

# 接收线程
class RecvData(QThread):
    recvThread1 = pyqtSignal(str, str)
    recvThread2 = pyqtSignal(str, str)
    recvThread3 = pyqtSignal(str)
    def __init__(self, parent = None):
        super(RecvData, self).__init__(parent)
        self.udpRecvSocket = socket(AF_INET,SOCK_DGRAM)

    def bindd(self,recvp):
        myRecvPort = recvp
        bindAddr = ('',myRecvPort)
        try:
            self.udpRecvSocket.bind(bindAddr)
            print("Success")
        except OSError:
            #弹窗
            print("Error")
            return False
        return True

    def run(self):
        while True:
            try:
                redata0 = self.udpRecvSocket.recv(1024)
                redata = redata0.decode('utf-8','ignore')
                #得到公钥
                if redata[:14]=='[#1]PublicKey(':
                    global opporsaPubK
                    tmpn = redata[14:-1]
                    tmpn = tmpn.split(',')
                    n = int(tmpn[0])
                    e = int(tmpn[1][1:])
                    opporsaPubK = algorithm.rsa_crypto(algorithm.rsa.PublicKey(n,e),None)
                    self.recvThread1.emit(("%x" % e),
                        '[#1]成功获得公钥:\n' + str(n) +'\n' + str(e) )
                #密钥交换
                elif redata[:13]=='[#2]ChangeKey':
                    global myrsaPubPriobj
                    msg = redata[13:]
                    tm = msg[:-128]
                    msg2 = a2b_hex(msg[-128:])
                    msg1 = algorithm.Md5().get_token(tm).upper()
                    res = str(b2a_hex(myrsaPubPriobj.rsa_decrypt(msg2))).upper()[2:-1]
                    if res == msg1:
                        self.recvThread2.emit(str(algorithm.bytes2int(a2b_hex(tm))),'成功获得交换密钥:\n'+tm)
                    else:
                        self.recvThread2.emit('Error','签名认证错误.')

                #信息传递
                else:
                    aeskey = Global_Var.Get_value('PbKey')
                    aeskey = ("%x"%aeskey)
                    if len(aeskey) < 32:
                        aeskey = '0'*32 + aeskey
                    aeskey = a2b_hex(aeskey[-32:])
                    r = algorithm.aes_crypto(aeskey)
                    res = (r.decrypt(redata0)).decode('utf-8','ignore')
                    self.recvThread3.emit(res)

                #输出内容
            except error as e:
                print(e)


# 发送线程
class SendData(QThread):
    sendThread = pyqtSignal(str)
    def __init__(self, parent = None):
        super(SendData, self).__init__(parent)
        self.udpSendSocket = socket(AF_INET,SOCK_DGRAM)

    def run(self):
        time.sleep(1)
        ip = Global_Var.Get_value('ip')
        port = int(Global_Var.Get_value('port'))
        sedata = Global_Var.Get_value('sedata')
        sendAddr = (ip,port)
        #发送公钥
        if sedata[:14] == '[#1]PublicKey(':
            sedata = sedata.encode('utf-8')
            self.udpSendSocket.sendto(sedata,sendAddr)
            self.sendThread.emit('成功发送公钥.\n')
        #密钥交换
        elif sedata[:13] == '[#2]ChangeKey':
            sedata = sedata.encode('utf-8')
            self.udpSendSocket.sendto(sedata,sendAddr)
            self.sendThread.emit('成功发送交换密钥.\n')

        #信息传递
        else:
            aeskey = Global_Var.Get_value('PbKey')
            aeskey = a2b_hex(("%x"%aeskey)[-32:])
            r = algorithm.aes_crypto(aeskey)
            sedata = sedata.encode('utf-8')
            sedata = r.encrypt(sedata)
            self.udpSendSocket.sendto(sedata,sendAddr)
            self.sendThread.emit('发送成功.\n')


if __name__ == "__main__":
    global_iv = Random.new().read(8)
    rsaobj = algorithm.rsa_crypto()
    global_LF1 = [1]
    global_LF1.extend(algorithm.get_str_bits(b'ACDjklad153adFwd'))
    global_LF2 = [0]
    global_LF2.extend(algorithm.get_str_bits(b'Mwf5ihwFShQf165Af'))
    app = QtWidgets.QApplication(sys.argv)
    window = Main()
    window.show()
    sys.exit(app.exec_())