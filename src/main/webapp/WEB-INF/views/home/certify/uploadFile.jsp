<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<meta content="" name="descriptison">
<meta content="" name="keywords">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />

</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />


		<!-- ======= Main ======= -->
		<div id="wrapper">
			<!-- ======= Certifify Section ======= -->
			<section id="certify"
				class="container d-flex align-items-center justify-content-center">
				<div
					class="container-fluid d-flex align-items-center justify-content-center">
					<div class="col-12">
 						<h2 class="page-title"><spring:message code="certify.title"></spring:message></h2>
						<p class="card-text"><spring:message code="certify.text"></spring:message></p>
						<div class="card shadow">
							<div class="card-body">
								<div
									class="row col-lg-12 align-items-center justify-content-center ">
									<div class="section-title" data-aos="fade-up">
										<h2><spring:message code="certify.title"></spring:message></h2>
										<p><spring:message code="certify.text"></spring:message></p>
									</div>
								</div>
								<div
									class="row col-lg-12 d-flex align-items-center justify-content-center">
									<div class="section-discription">
										<p>
										<spring:message code="certify.descript"></spring:message>
										</p>
									</div>
								</div>
								<div
									class="row col-lg-12 d-flex align-items-center justify-content-center">
									<form action="${ pageContext.request.contextPath }/certify"
										method="post" name="certUpload" enctype="multipart/form-data">
										<ul>
											<li><input type="file" name="regCard"></li>
											<li><input type="submit" value="<spring:message code="register"></spring:message>"
												class="btn btn-primary w-100" style="margin-left: 0">
												<i class="fe fe-upload fe-16"></i></li>
										</ul>
									</form>
								</div>
							</div>
						</div>
					</div>
				</div>
			</section>
		</div>
		<!-- End Certifify Section -->
	<script>
		function doRegister() {
			//파일 확장자 체크
			if (checkExt(f.attachfile1)) {
				return false; // 확장자 위배시 바로 false 리턴하며 doWrite 메소드 종료
			}
			if (checkExt(f.attachfile2)) {
				return false;
			}
			return true;
		}

		function checkExt(obj) {
			let needed = [ 'jpg', 'png', 'gif' ];
			let fileName = obj.value;
			let ext = fileName.substring(fileName.lastIndexOf('.') + 1);

			for (let i = 0; i < needed.length; i++) {
				if (needed != ext) {
					alert('이미지 파일만 업로드할 수 있습니다.<br>(가능 확장자:jpg, png, gif)');
					return true;
				}
			}
			return false;
		}
	</script>


	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />

	<!-- End Footer -->
</body>
</html>