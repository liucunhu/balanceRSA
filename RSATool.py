"""
======================
@author:LCH
@time:2022/6/22:14:12
@email:786608954@qq.com
======================
"""
# --*--encoding:utf-8--*--
import base64
import rsa
import os
class RsaTool:

    def __init__(self,size):
        self.size=size
    def __saveKeysFile(self,filename,keys):
        '''
        保存密钥
        :param filename:
        :param keys:
        :return:
        '''

        try:

            with open(filename,mode='w') as data:
                data.write(keys)

        except Exception as e:

            print(f'密钥存储异常{e}')
    def __readKeysFile(self,filename):
        '''
        公钥读取
        :param filename:
        :return:
        '''

        try:
            with open(filename,mode='r') as data:
                keycontent=data.read()
            return keycontent
        except Exception as e:
            print(f'读取文件异常{e}')
            return None
    def generatingKey(self,filename):
        '''
        生成并保存rsa密钥
        :param filename:
        :return:
        '''
        (pub,privkey)=rsa.newkeys(self.size)

        pub=pub.save_pkcs1()
        pri=privkey.save_pkcs1()

        pubname=os.path.join(filename,'pubkey.pem')
        priname=os.path.join(filename,'prikey.pem')

        self.__saveKeysFile(pubname,pub.decode())
        self.__saveKeysFile(priname,pri.decode())

        print(f'RSA密钥生成成功保存为公钥{pubname}和私钥{priname}')
        return (pub,privkey)
    def readPubKey(self,filename):
        '''
        通过文件读取公钥
        :param filename:
        :return:
        '''

        pubkey=self.__readKeysFile(filename)
        if pubkey:
            if 'BEGIN RSA PUBLIC KEY' in pubkey:
                keystring=rsa.PublicKey.load_pkcs1(pubkey.encode('utf-8'))

            else:
                keystring=f'''-----BEGIN RSA PUBLIC KEY-----\n{pubkey}\n-----END RSA PUBLIC KEY-----'''
                keystring=rsa.PublicKey.load_pkcs1(keystring.encode('utf-8'))

            return keystring
        else:
            return None
    def readPriKey(self,filename):
        '''
        通过文件读取私钥
        :param self:
        :param filename:
        :return:
        '''
        prikey = self.__readKeysFile(filename)
        if prikey:
            if '-----BEGIN RSA PRIVATE KEY-----' in prikey:
                keystring = rsa.PrivateKey.load_pkcs1(prikey.encode('utf-8'))

            else:
                keystring = f'''-----BEGIN RSA PRIVATE KEY-----\n{prikey}\n-----END RSA PRIVATE KEY-----'''
                keystring = rsa.PrivateKey.load_pkcs1(keystring.encode('utf-8'))

            return keystring
        else:
            return None
    def enStringWthPub(self,message,pubkey):
        '''
        公钥加密
        :param message:
        :param pubkey:
        :return:
        '''
        if pubkey:
            try:
                keystring=pubkey
            except Exception as e:

                if 'BEGIN RSA PUBLIC KEY' in pubkey:
                    keystring = rsa.PublicKey.load_pkcs1(pubkey.encode('utf-8'))

                else:
                    keystring = f'''-----BEGIN RSA PUBLIC KEY-----\n{pubkey}\n-----END RSA PUBLIC KEY-----'''
                    keystring = rsa.PublicKey.load_pkcs1(keystring.encode('utf-8'))
            msg=message.encode('utf-8')
            enmsg=rsa.encrypt(msg,keystring)
            print(f'加密后的数据为：{base64.b64encode(enmsg).decode("utf-8")}')
            return base64.b64encode(enmsg).decode("utf-8")

    def decryptMessage(self,enmessage,prikey):
        '''
        私钥解密
        :param enmessage:
        :param prikey:
        :return:
        '''
        try:
            prikeyString=prikey
        except Exception as e:

            if '-----BEGIN RSA PRIVATE KEY-----' in prikey:
                prikeyString = rsa.PrivateKey.load_pkcs1(prikey.encode('utf-8'))

            else:
                keystring = f'''-----BEGIN RSA PRIVATE KEY-----\n{prikey}\n-----END RSA PRIVATE KEY-----'''
                prikeyString = rsa.PrivateKey.load_pkcs1(keystring.encode('utf-8'))
        enMessage=base64.b64decode(enmessage.encode('utf-8'))
        deString=rsa.decrypt(enMessage,prikeyString)
        print(deString.decode('utf-8'))
        return deString.decode('utf-8')
    def signMessage(self,prikey,sigmsg):
        hash=rsa.compute_hash(sigmsg.encode('utf-8'),'SHA-1')
        signature=rsa.sign_hash(hash,prikey,'SHA-1')
        signdata=base64.b64encode(signature)

        #print(signdata)
        return signdata
    def verifySign(self,pub,sigmsg,sigString):
        #print(base64.b64decode(sigmsg.encode('utf-8')))
        sigmsg=base64.b64decode(sigmsg.encode('utf-8'))
        try:
            rsa.verify(sigString.encode('utf-8'),sigmsg,pub)

            return True
        except Exception as e:
            print(f'验签失败:{e}')
            return False


if __name__ == '__main__':
    keys=RsaTool(1024)
    path='D:\myfile\keys\pubkey.pem'
    pubkey=keys.readPubKey(path)
    message=' Python 的面向对象开发过程中,对象的某些方法或者称为函数只想在对象的内部被使用,但不想在外部被访问到这些方法或函数。 即:私有方法是对象不愿意公开的方法或函数'
    pri='D:\myfile\keys\prikey.pem'
    prikey=keys.readPriKey(pri)
    #enmsg=keys.enStringWthPub(message,pubkey)
    #demsg=keys.decryptMessage(enmsg,prikey)
    messages='hello'
    signdata=keys.signMessage(prikey,messages).decode('utf-8')
    #print(signdata)
    msg1='hello'
    print(keys.verifySign(pubkey,signdata,msg1))
