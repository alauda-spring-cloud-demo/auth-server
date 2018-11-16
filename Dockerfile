FROM registry-vpc.cn-beijing.aliyuncs.com/linkme/java:8-pinpoint

COPY target/*.jar /app/app.jar

# CMD java ${JAVA_OPTS} \
# 	-Djava.security.egd=file:/dev/./urandom \
# 	-jar /app/app.jar

CMD java ${JAVA_OPTS} \
	-Djava.security.egd=file:/dev/./urandom \
	-javaagent:/pinpoint-agent/pinpoint-bootstrap-1.8.0.jar \
	-Dpinpoint.agentId=${APP_NAME} \
	-Dpinpoint.applicationName=${APP_NAME} \
	-jar /app/app.jar