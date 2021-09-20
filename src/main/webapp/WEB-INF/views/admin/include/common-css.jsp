<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
 <!-- Simple bar CSS -->
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/simplebar.css">
    <!-- Fonts CSS -->
    <link href="https://fonts.googleapis.com/css2?family=Overpass:ital,wght@0,100;0,200;0,300;0,400;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">
    <!-- Icons CSS -->
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/feather.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/select2.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/dropzone.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/uppy.min.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/jquery.steps.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/jquery.timepicker.css">
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/quill.snow.css">
    <!-- Date Range Picker CSS -->
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/daterangepicker.css">
    <!-- App CSS -->
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/app-dark.css" id="darkTheme" disabled>
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/assets/css/app-light.css" id="lightTheme">
    
<style>
    
@font-face {
  font-family: "hana";
  src: url(${ pageContext.request.contextPath }/resources/fonts/HanaL.ttf) format('ttf');
  font-weight: 300;
}
@font-face {
  font-family:"hana";
  src: url(${ pageContext.request.contextPath }/resources/fonts/HanaM.ttf) format('ttf');
  font-weight: normal;
}
@font-face {
  font-family: "hana";
  src: url(${ pageContext.request.contextPath }/resources/fonts/HanaB.ttf) format('truetype');
  font-weight: 500;
}

@font-face {
	font-family: hanaL;
	src: url(${ pageContext.request.contextPath }/resources/fonts/HanaL.ttf) format('truetype');
	font-style: normal;
	font-weight: normal;
}

@font-face {
	font-family: hanaM;
	src: url(${ pageContext.request.contextPath }/resources/fonts/HanaM.ttf) format('truetype');
	font-style: normal;
	font-weight: normal;
}

@font-face {
	font-family: hanaB;
	src: url(${ pageContext.request.contextPath }/resources/fonts/HanaB.ttf) format('truetype');
	font-style: normal;
	font-weight: normal;
}

@font-face {
	font-family: hanaUL;
	src: url(${ pageContext.request.contextPath }/resources/fonts/HanaUL.ttf) format('truetype');
	font-style: normal;
	font-weight: normal;
}

@font-face {
	font-family: hanaCM;
	src: url(${ pageContext.request.contextPath }/resources/fonts/HanaCM.ttf) format('truetype');
	font-style: normal;
	font-weight: normal;
}

.hanaM {
	font-family: hanaM;
}
.hanaUL {
	font-family: hanaUL;
}

.page-title {
    	font-family: hanaM;
    	font-weight: 500;
/*     	color: #0a8485; */
    	color: #17a2b8;
}
    
    </style>