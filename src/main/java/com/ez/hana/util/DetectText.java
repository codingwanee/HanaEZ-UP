package com.ez.hana.util;

import com.google.cloud.vision.v1.AnnotateImageRequest;
import com.google.cloud.vision.v1.AnnotateImageResponse;
import com.google.cloud.vision.v1.BatchAnnotateImagesResponse;
import com.google.cloud.vision.v1.EntityAnnotation;
import com.google.cloud.vision.v1.Feature;
import com.google.cloud.vision.v1.Image;
import com.google.cloud.vision.v1.ImageAnnotatorClient;
import com.google.protobuf.ByteString;
//import com.google.protobuf.DescriptorProtos.GeneratedCodeInfo.Annotation;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


public class DetectText {
	
  public static String detectText() throws IOException {
//    String filePath = "path/to/your/image/file.jpg";
	  
    String filePath = "D:/fileStorage/regcard1.jpg";
    String detectedStr = detectText(filePath);
    
    return detectedStr;
  }

  // Detects text in the specified image.
  public static String detectText(String filePath) throws IOException {
	  // 반환할 문자열 변수 생성
	  StringBuilder sb = new StringBuilder();

	  List<AnnotateImageRequest> requests = new ArrayList<>();

    ByteString imgBytes = ByteString.readFrom(new FileInputStream(filePath));

    Image img = Image.newBuilder().setContent(imgBytes).build();
    Feature feat = Feature.newBuilder().setType(Feature.Type.TEXT_DETECTION).build();
    AnnotateImageRequest request =
    		AnnotateImageRequest.newBuilder().addFeatures(feat).setImage(img).build();
    requests.add(request);

    // Initialize client that will be used to send requests. This client only needs to be created
    // once, and can be reused for multiple requests. After completing all of your requests, call
    // the "close" method on the client to safely clean up any remaining background resources.
    try (ImageAnnotatorClient client = ImageAnnotatorClient.create()) {
      BatchAnnotateImagesResponse response = client.batchAnnotateImages(requests);
      List<AnnotateImageResponse> responses = response.getResponsesList();

      for (AnnotateImageResponse res : responses) {
        if (res.hasError()) {
          System.out.format("Error: %s%n", res.getError().getMessage());
          return "Error";
        }
                        
        int index=0;
        // For full list of available annotations, see http://g.co/cloud/vision/docs      
        for (EntityAnnotation annotation : res.getTextAnnotationsList()) {
        	if(index==0) {        		
        		sb.append(annotation.getDescription());
        		sb.toString();
        	}
        	index++;
        	/*
          System.out.format("Text: %s%n", annotation.getDescription());
          System.out.format("Position : %s%n", annotation.getBoundingPoly());
        	 */
        }
        
      }
    }
    
    String detectedStr = sb.toString();
        
    return detectedStr;
  }
  
}