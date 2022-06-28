"""
======================
@author:LCH
@time:2022/6/27:15:32
@email:786608954@qq.com
======================
"""
# --*--encoding:utf-8--*--
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import  pad,unpad

class MyAESTool:
    def __add_to_16(self,data):
        datalen=len(data)

        if datalen%16==0:
            return data
        else:
            paddata=16-datalen%16
            data=data+chr(0)*paddata

            return data

    def enString(self,key,message):
        BLOCK_SIZE=16
        aes=AES.new(self.__add_to_16(key).encode('utf-8'),AES.MODE_ECB)
        encrypt_aes=aes.encrypt(pad(message.encode('utf-8'),BLOCK_SIZE))
        str_msg=base64.encodebytes(encrypt_aes)

        return str_msg.decode('utf-8')

    def deString(self,key,enmessage):
        aes=AES.new(self.__add_to_16(key).encode('utf-8'),AES.MODE_ECB)
        destring=aes.decrypt(base64.decodebytes(enmessage.encode('utf-8')))
        #print(destring.decode('utf-8'))

        return destring.decode("utf-8")

if __name__ == '__main__':
    keys='1998-820123123123'
    aest=MyAESTool()
    msg='我的测试数据'
    enstrs=aest.enString(keys,msg)

    destrs=aest.deString(keys,enstrs)
    with open('somedata.txt','w',encoding='utf-8') as f:
        f.write(destrs)
    print(f'解密后的数据{destrs}')

