package com.phishguard;

import org.springframework.context.annotation.DependsOn:
import org.springframework.stereotype.Service;
import weka.classifiers.Classifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.File;
import java.util.ArrayList;

@Service
@DependsOn("modelTrainer")
public class PhishingDetectorService {

    private final UrlFeatureExtractor extractor = new UrlFeatureExtractor();
    private final Classifier classifier;
    private final Instances header;

    public PhishingDetectorService() {
        try {
            File modelFile = new File("model/phishing-model.model");
            if (!modelFile.exists()) {
                throw new IllegalStateException("ML model does not exist yet.");
            }

            classifier = (Classifier) SerializationHelper.read(modelFile.getAbsolutePath());

            ArrayList<Attribute> attributes = new ArrayList<>();
            for (String name : UrlFeatureExtractor.ATTRIBUTE_NAMES) {
                attributes.add(new Attribute(name));
            }
            ArrayList<String> classes = new ArrayList<>();
            classes.add("benign");
            classes.add("phishing");
            attributes.add(new Attribute("class", classes));

            header = new Instances("PhishingURL", attributes, 0);
            header.setClassIndex(header.numAttributes() - 1);
        } catch (Exception e) {
            throw new IllegalStateException("Could not load phishing model: " + e.getMessage(), e);
        }
    }

    public PredictionResult predict(String rawUrl) {
        try {
            String normalized = extractor.normalize(rawUrl);
            double[] features = extractor.extract(normalized);

            DenseInstance instance = new DenseInstance(header.numAttributes());
            instance.setDataset(header);

            for (int i = 0; i < features.length; i++) {
                instance.setValue(i, features[i]);
            }

            double prediction = classifier.classifyInstance(instance);
            double[] distribution = classifier.distributionForInstance(instance);

            String label = header.classAttribute().value((int) prediction);
            double confidence = distribution[(int) prediction] * 100.0;

            // A transparent demo risk score combining model confidence with URL heuristics.
            // This is a presentation score, not a standardized security metric.
            double risk = label.equals("phishing")
                    ? Math.max(confidence, heuristicRisk(features))
                    : Math.min(confidence, heuristicRisk(features));

            risk = Math.max(0, Math.min(100, risk));

            return new PredictionResult(
                    normalized,
                    label,
                    round(confidence),
                    round(risk),
                    extractor.indicators(normalized)
            );
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not analyze URL: " + e.getMessage());
        }
    }

    private double heuristicRisk(double[] f) {
        double score = 5;
        if (f[0] > 75) score += 10;
        if (f[3] >= 4) score += 10;
        if (f[5] > 0) score += 18;
        if (f[10] >= 2) score += 12;
        if (f[11] > 0) score += 18;
        if (f[12] == 0) score += 8;
        if (f[13] > 0) score += 12;
        if (f[14] > 0) score += 10;
        if (f[15] > 0) score += 5;
        if (f[16] > 4.0) score += 8;
        return Math.min(100, score);
    }

    private double round(double value) {
        return Math.round(value * 10.0) / 10.0;
    }

    public record PredictionResult(
            String url,
            String prediction,
            double confidence,
            double riskScore,
            String[] indicators
    ) {}
}
