生成公私钥（密钥对）
cmd执行命令：keytool -genkeypair -keystore my.jks -storepass 123456 -alias my-key -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -v
填写必要的信息，最后确认 Y。生成一个 my.jks 密钥对文件。将它放到请求方项目 src/main/resources 中。