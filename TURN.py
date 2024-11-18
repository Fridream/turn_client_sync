import os,time
import hashlib
import struct
import queue
import threading

class TURN_CLIENT:

    # 使用指南:
    # 1.connect 获取中继IP
    # 2.bind 绑定对端IP
    # 3.send/recv 收发数据

    # 注意事项:
    # 1.实际数据均通过0x7777通道收发
    # 2.一个实例仅支持一个通道
    # 3.需要较频繁调用send/recv

    from aioice.stun import Message,Method,Class
    from aioice.stun import parse_message

    def __init__(self,sock,username,credential):
        # 在数据通道打开后，请求响应会混淆数据
        # 由用户发送接收真实数据时发送请求接收响应
        self.requests=queue.Queue()
        self.responses=dict()
        if not sock or not username or not credential:
            raise ValueError()
        self.sock=sock;self.username=username
        self.credential=credential

    def bind(self,peer_relayed_address,refresh=False):
        # 创建BIND REQUEST，使用固定隧道号0x7777
        request=TURN_CLIENT.Message(TURN_CLIENT.Method.CHANNEL_BIND,TURN_CLIENT.Class.REQUEST)
        request.attributes["CHANNEL-NUMBER"]=0x7777
        request.attributes["XOR-PEER-ADDRESS"]=peer_relayed_address
        # 如果是用户执行则表示第一次绑定，直接请求，否则为刷新，加入队列等待发送
        if not refresh: response=self.response(request)
        else: self.requests.put(request);response=self.wait_response(request)

        # 判断绑定是否成功，成功则启动定时刷新线程
        if response.message_class!=TURN_CLIENT.Class.RESPONSE: raise RuntimeError()
        refresh_bind=lambda:(time.sleep(500),self.bind(peer_relayed_address,True))
        self.bind_loop=threading.Thread(target=refresh_bind)
        self.bind_loop.start()

    def connect(self):
        # 创建ALLOCATE REQUEST，LIFETIME不传递，使用服务器默认值，TCP 0x06000000;UDP 0x11000000
        request=TURN_CLIENT.Message(TURN_CLIENT.Method.ALLOCATE,TURN_CLIENT.Class.REQUEST)
        request.attributes["REQUESTED-TRANSPORT"]=0x06000000
        response=self.response(request)

        # 正常会返回401未授权，添加用户名和通过凭证构建的完整性数据再次发送
        if response.message_class!=TURN_CLIENT.Class.ERROR: raise RuntimeError()
        if response.attributes['ERROR-CODE'][0]!=401: raise RuntimeError()
        self.nonce=response.attributes["NONCE"]
        self.realm=response.attributes["REALM"]
        self.integrity_key=':'.join([self.username,self.realm,self.credential]).encode()
        self.integrity_key=hashlib.md5(self.integrity_key).digest()
        request.transaction_id=os.urandom(12) # 重新创建ID
        response=self.response(request)

        # 判断申请是否成功，成功则启动定时刷新线程并返回中继地址
        if response.message_class!=TURN_CLIENT.Class.RESPONSE: raise RuntimeError()
        refresh_time=response.attributes["LIFETIME"]*6/5
        self.relayed_address=response.attributes["XOR-RELAYED-ADDRESS"]
        self.refresh_loop=threading.Thread(target=self.refresh,args=(refresh_time,))
        self.refresh_loop.start()

        return self.relayed_address

    def recv(self):
        raw_data_info=self.sock.recv(4)
        info,length=struct.unpack("!HH",raw_data_info)
        # 只有是固定隧道号0x7777才判断为隧道数据
        if info==0x7777:
            # TCP相关的传输方式必须补齐4字节倍数的大小
            user_data=self.sock.recv(length)
            self.sock.recv((4-length%4)%4)
            return user_data
        response=raw_data_info+self.sock.recv(16+length)
        # stun标准包必定是4的倍数大小，不用丢弃
        response=TURN_CLIENT.parse_message(response)
        self.responses[response.transaction_id]=response
        # 因是用户请求所以需要再次尝试读取隧道数据
        return self.recv()

    def wait_response(self,request):
        # 循环检查指定请求的传输号对应的响应是否已经返回
        transaction_id=request.transaction_id
        while transaction_id not in self.responses: time.sleep(1)
        response=self.responses.pop(transaction_id)
        if response.message_class!=TURN_CLIENT.Class.ERROR: return response
        error_code=response.attributes.get('ERROR-CODE',None)
        if not error_code or error_code[0]!=438: return response
        # 如果是438错误nonce过期了则更新后重新请求
        self.nonce=response.attributes["NONCE"]
        integrity=':'.join([self.username,self.realm,self.credential]).encode()
        self.integrity_key=hashlib.md5(integrity).digest()
        request.transaction_id=os.urandom(12) # 重新创建ID
        self.requests.put(request);return self.wait_response(request)

    def refresh(self,expire_time):
        time.sleep(expire_time)
        # 创建REFRESH REQUEST，LIFETIME不传递，使用服务器默认值，0除外表示注销
        request=TURN_CLIENT.Message(TURN_CLIENT.Method.REFRESH,TURN_CLIENT.Class.REQUEST)
        if expire_time==0:request.attributes["LIFETIME"]=0;response=self.response(request)
        else: self.requests.put(request);response=self.wait_response(request)

        # 判断申请是否成功，成功则再次按照存活时间启动刷新线程，0除外
        if response.message_class!=TURN_CLIENT.Class.RESPONSE: raise RuntimeError()
        if expire_time==0: return
        refresh_time=response.attributes["LIFETIME"]*6/5
        self.refresh_loop=threading.Thread(target=self.refresh,args=(refresh_time,))
        self.refresh_loop.start()

    def close(self):
        import ThreadUtils
        ThreadUtils.stopThread(self.bind_loop)
        ThreadUtils.stopThread(self.refresh_loop)
        self.refresh(0) # 刷新0s表示注销申请
        self.sock.close()

    def request(self,request):
        # 如果有则添加用户凭证，对整个消息进行完整性保护
        if hasattr(self,'integrity_key'):
            request.attributes["USERNAME"]=self.username
            request.attributes["NONCE"]=self.nonce
            request.attributes["REALM"]=self.realm
            request.add_message_integrity(self.integrity_key)
        # stun标准包必定是4的倍数大小，不用填充直接发送
        self.sock.sendall(bytes(request))

    def response(self,request):
        # 仅在数据通道未打开时，直接发送请求并获取返回
        self.request(request)
        raw_head=self.sock.recv(20)
        body_len=struct.unpack("!HHI12s",raw_head)[1]
        raw_data=raw_head+self.sock.recv(body_len)
        # stun标准包必定是4的倍数大小，不用丢弃
        return TURN_CLIENT.parse_message(raw_data)

    def send(self,data):
        # 发送用户消息前先检查是否有待发请求，优先请求
        while not self.requests.empty():
            self.request(self.requests.get(block=False))
        header=struct.pack("!HH",0x7777,len(data))
        # TCP相关的传输方式必须补齐4字节倍数的大小
        padding=bytes((4-len(data)%4)%4)
        self.sock.sendall(header+data+padding)