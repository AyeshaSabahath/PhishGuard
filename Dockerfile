FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

COPY pom.xml .

RUN mvn dependency:go-offline -B

COPY src ./src
COPY dataset ./dataset
COPY frontend ./frontend
COPY model ./model

RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar
COPY --from=build /app/dataset ./dataset
COPY --from=build /app/frontend ./frontend
COPY --from=build /app/model ./model

EXPOSE 10000

CMD ["sh", "-c", "java -jar app.jar --server.port=${PORT:-10000}"]