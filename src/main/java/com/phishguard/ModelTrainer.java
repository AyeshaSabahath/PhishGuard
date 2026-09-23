package com.phishguard;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import weka.classifiers.Classifier;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.CSVLoader;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

@Component
public class ModelTrainer {

    private final String modelPath = "model/phishing-model.model";
    private final String datasetPath = "dataset/phishing.csv";

    @PostConstruct
    public void ensureModelExists() {
        try {
            File model = new File(modelPath);
            if (!model.exists()) {
                System.out.println("[PhishGuard] ML model not found. Training Random Forest...");
                trainModel();
                System.out.println("[PhishGuard] Model saved to " + modelPath);
            } else {
                System.out.println("[PhishGuard] Existing ML model loaded from " + modelPath);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not prepare the ML model: " + e.getMessage(), e);
        }
    }

    public void trainModel() throws Exception {
        File datasetFile = new File(datasetPath);
        if (!datasetFile.exists()) {
            throw new IllegalStateException("Dataset not found: " + datasetPath);
        }

        CSVLoader loader = new CSVLoader();
        loader.setSource(datasetFile);
        Instances data = loader.getDataSet();

        if (data.classIndex() < 0) {
            data.setClassIndex(data.numAttributes() - 1);
        }

        RandomForest forest = new RandomForest();
        forest.setNumIterations(120);
        forest.setSeed(42);
        forest.buildClassifier(data);

        File modelFile = new File(modelPath);
        modelFile.getParentFile().mkdirs();
        SerializationHelper.write(modelFile.getAbsolutePath(), forest);
    }
}
