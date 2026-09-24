# PhishGuard

AI-Powered Phishing URL Detection System built with Java, Spring Boot and Weka.

## Architecture

PhishGuard/
├── src/main/java/com/phishguard/       # Java backend + ML logic
├── model/                              # Weka model (created on first run)
├── dataset/phishing.csv                # Educational training dataset
├── frontend/                           # HTML/CSS/JS UI
└── pom.xml                             # Maven configuration

## Requirements

- Java 17 or newer
- Maven 3.9+
- Internet access on the first Maven build so Maven can download dependencies

## Run

1. Open a terminal in the PhishGuard folder.
2. Check Java:
   java -version
3. Check Maven:
   mvn -version
4. Start:
   mvn spring-boot:run
5. Open:
   http://localhost:8080

On the first startup, PhishGuard automatically trains a Weka Random Forest model from dataset/phishing.csv and saves:
model/phishing-model.model

## Alternative build/run

mvn clean package
java -jar target/phishguard-1.0.0.jar

Keep the `frontend`, `dataset`, and `model` folders beside the project when using `mvn spring-boot:run`.
For the simplest development/demo flow, use `mvn spring-boot:run`.

## How the ML part works

1. A URL is entered in the browser.
2. Java extracts 17 numerical URL features.
3. The saved Weka Random Forest classifier predicts `benign` or `phishing`.
4. A model confidence and a presentation-oriented risk score are returned.
5. Java also produces human-readable heuristic indicators.

## Features

- URL length
- hostname length
- path length
- dot count
- hyphen count
- @ symbol count
- query/parameter counts
- slash count
- digit count
- subdomain count
- IP-host detection
- HTTPS
- suspicious security keywords
- URL shortener detection
- non-standard port
- URL entropy

## Important academic note

The included CSV is a small, generated educational dataset designed to make the project self-contained and runnable without downloading a dataset. It is NOT a benchmark-quality phishing dataset. For a final research-grade system, replace it with a properly sourced dataset and report train/test methodology, class balance, precision, recall, F1-score, and ROC-AUC.

The displayed risk score is a project-specific presentation score, not a standardized security metric.

## Suggested demo URLs

Safe-style examples:
- https://www.google.com
- https://www.wikipedia.org
- https://github.com
- https://www.microsoft.com

Suspicious-style examples for demonstrating feature extraction:
- http://secure-login-verify.example.xyz/account/update
- http://192.168.1.20/login/verify/account

Do not enter real credentials or interact with unknown links.

## Troubleshooting

### Port 8080 is busy
Run:
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
Then open http://localhost:8081

### Model errors
Delete:
model/phishing-model.model

Then restart:
mvn spring-boot:run

The model will be regenerated.

## Viva explanation

"PhishGuard is a Java Spring Boot cybersecurity application that uses Weka Random Forest classification to identify potentially phishing URLs. The application extracts structural URL features such as URL length, subdomain count, HTTPS usage, suspicious keywords, IP-host usage and entropy. The trained classifier predicts whether a URL is benign or phishing, while the application also presents explainable heuristic indicators and a project-specific risk score."

## Authors:
- Ayesha Sabahath
- Adiba Parveen
- Mahek Sultana
- Radifa Khanam
