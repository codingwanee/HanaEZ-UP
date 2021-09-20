<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<meta content="" name="descriptison">
<meta content="" name="keywords">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<!-- common css -->
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

</head>
<body>

	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="branch-search"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title">하나은행 외국인 특화지점 통역사</h2>
					<p class="card-text">
						하나은행은 항상 세계 각국의 언어를 구사할 수 있는 통역사를 필요로 합니다.<br> 하나EZ멤버로 가입하시면
						외국인이 아닌 통역사도 게시판에 글을 쓰실 수 있습니다.
					</p>
					<div class="row align-items-center justify-content-center">
						<div class="col-md-8">
							<a
								href="${ pageContext.request.contextPath }/translator/register"><button
									class="btn btn-primary">지원하러 가기</button></a>
						<img
							src="${ pageContext.request.contextPath }/resources/images/translator.png"
							class="img-fluid animated" alt="main-fluid-img"
							style="width: 100%">
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>