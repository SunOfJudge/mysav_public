# mysav_public

mysav源地址验证部署测量工具，探针节点发布版本

## 安装依赖

- 安装python3.7.0，安装包见 `env/python3`

- 安装依赖项，请运行 `env` 文件夹下的 `install.sh` 或 `install.bat`

## 运行方法

- 运行根目录下的 `start.sh` 或 `start.bat`

## 注意事项

- windows下请关闭防火墙进行测试，否则可能导致本地探针无法被连接。关闭方法：“控制面板” - “网络和共享中心” - “Windows Defender 防火墙” - “启用或关闭 Windows Defender 防火墙” - 关闭防火墙

- linux等平台下，运行shell脚本请使用root权限，否则探针将无法发出测试数据包
