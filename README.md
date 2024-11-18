# turn_client_sync
TURN客户端同步版

由aioice包中turn.py代码修改而来，去除异步相关逻辑，改为socket+同步

限制：不再支持send_data方法实时绑定channel，不再支持一对多channel，需要预先手动绑定，后续无需再传对等体地址
