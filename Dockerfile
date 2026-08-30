# Runtime image for Cloud Run and for the local compose "services" profile.
# The jar is built outside the image (mvn package locally; Cloud Build in stage 2), so the image
# only carries a JRE and the artifact. PORT is the Cloud Run contract; the default matches
# docs/implementation-plan.md.
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/student360-auth-service-*.jar /app/app.jar
ENV PORT=8081
EXPOSE 8081
USER 65532:65532
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
