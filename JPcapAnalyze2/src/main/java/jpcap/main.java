package main.java.jpcap;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.Map;

import net.sf.javaml.classification.Classifier;
import net.sf.javaml.classification.KNearestNeighbors;
import net.sf.javaml.classification.evaluation.CrossValidation;
import net.sf.javaml.classification.evaluation.EvaluateDataset;
import net.sf.javaml.classification.evaluation.PerformanceMeasure;
import net.sf.javaml.core.Dataset;
import net.sf.javaml.tools.data.FileHandler;

public class main {

	public static void main(String[] args) throws Exception {

		//		String inputDiractory = args[0];
		//		String outDiractory = args[1]; 

		String inputDiractory = "C:\\temp\\JPcapAnalyze-recordes\\source_files\\test\\in";
		String outDiractory = "C:\\temp\\JPcapAnalyze-recordes\\source_files\\test\\out"; 

		File folder = new File(inputDiractory);
		File[] listOfFiles = folder.listFiles();
		for (File file : listOfFiles) {
			System.out.println(file.getName());
			if (file.isFile()) {
				ProcessBuilder builder = new ProcessBuilder(
						"cmd.exe", "/c", "cd SplitCap"+ " && SplitCap -r " +inputDiractory+"\\"+file.getName()+ " -o "+outDiractory+ " -b 50000");
				builder.redirectErrorStream(true);
				Process p = builder.start();
				BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line;
				line = r.readLine();
				if (line == null) { break; }
				p.destroy();
			}
		}
		
		java.util.concurrent.TimeUnit.SECONDS.sleep(5);

		String csvFileAll = inputDiractory +"\\allSession.csv";
		BufferedWriter writer = new BufferedWriter(new FileWriter(csvFileAll));
		String line;
//		String line ="Mean, Variance, StandardDeviation, Skew, Kurtosis,";
//		for(int i=0 ; i < 12; i++){
//			writer.write(line);
//		}
//		writer.write("\n");
		
		File out = new File(outDiractory);
		File[] listOfPcap = out.listFiles();
		AnalyzePcap analyzer;
		String fileName;
		for (File file : listOfPcap) {
			fileName = file.getName();
			if(!fileName.endsWith(".pcap")){
				continue;
			}
			analyzer = new AnalyzePcap(); 
			line = analyzer.run(outDiractory+"\\"+fileName);
			if(line != null){
				writer.write(line);			
			}
		}	
		writer.close();
		java.util.concurrent.TimeUnit.SECONDS.sleep(1);
		deleteFolder(outDiractory);
		for(int i=0 ;i<10 ; i++){
			if(!deleteFolder(outDiractory)){
				break;
			}
		}
		getKnnAnalysis(csvFileAll);
	}

	private static boolean deleteFolder(String outDirectory){
		File file  = new File(outDirectory);
		String[] entries = file.list();
		if(entries == null){
			return false;
		}
		System.out.println("total files ="+entries.length);
		for(String s: entries){
		    File currentFile = new File(file.getPath(),s);
		    currentFile.delete();
		}
		System.out.println("deleted directory "+ outDirectory);
		file.delete();
		return true;
	}
	
	private static void getKnnAnalysis(String filePath) throws Exception {
	    Dataset data = FileHandler.loadDataset(new File(filePath), 60, ",");
        /*
         * Contruct a KNN classifier that uses 5 neighbors to make a decision.
         */
        Classifier knn = new KNearestNeighbors(5);
        knn.buildClassifier(data);

        /*
         * Load a data set for evaluation, this can be a different one, but for
         * this example we use the same one.
         */
        Dataset dataForClassification = FileHandler.loadDataset(new File(filePath), 60, ",");

        Map<Object, PerformanceMeasure> pm = EvaluateDataset.testDataset(knn, dataForClassification);
        for (Object o : pm.keySet())
            System.out.println(o + ": " + pm.get(o).getAccuracy());
        System.out.println("With CrossValidation: ");
        getkNNCrossValidation(filePath);
	}
	
	public static void getkNNCrossValidation(String filePath)throws Exception {
		   /* Load data */
  Dataset data = FileHandler.loadDataset(new File(filePath), 60, ",");
  /* Construct KNN classifier */
  Classifier knn = new KNearestNeighbors(5);
  /* Construct new cross validation instance with the KNN classifier */
  CrossValidation cv = new CrossValidation(knn);
  /* Perform 5-fold cross-validation on the data set */
  Map<Object, PerformanceMeasure> p = cv.crossValidation(data);

  System.out.println("Accuracy cnn=" + p.get("cnn").getAccuracy());
  System.out.println(p);
  System.out.println("Accuracy amazon=" + p.get("amazon").getAccuracy());
  System.out.println(p);
  System.out.println("Accuracy facebook=" + p.get("facebook").getAccuracy());
  System.out.println(p);
	}
}

