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
	<!-- ======= LOGIN SECTION ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="login" class="container"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid align-items-center justify-content-center">
				<div class="row col-sm-12 align-items-center justify-content-center">
					<p class="card-text"></p>
					<div class="row col-sm-6">
						<div class="col-sm-12">
							<div class="login-form align-items-center">
								<form action="${ pageContext.request.contextPath }/login"
									method="post">
									<h2 class="text-center page-title m-5">
										<spring:message code="member.login"></spring:message>
									</h2>
									<p class="align-center">
									&nbsp;&nbsp;&nbsp;<spring:message code="member.login.text"></spring:message><br>
									</p>
									<div class="form-group p-2 mb-0">
										<div class="input-group">
											<input type="text" class="form-control" name="id"
												placeholder="id" required="required">
										</div>
									</div>
									<div class="form-group p-2 mb-0">
										<div class="input-group">
											<input type="password" class="form-control" name="password"
												placeholder="password" required="required">
										</div>
									</div>
									<div class="form-group p-0">
										<div class="input-group p-0 m-0">
											<input type="submit"
												class="btn btn-primary login-btn btn-block" value="<spring:message
											code="member.login"></spring:message>">
										</div>

									</div>
									<!--
									 	<div class="clearfix">
											<label class="float-left form-check-label"><input
												type="checkbox"> Remember me</label> <a href="#"
												class="float-right">Forgot Password?</a>
										</div>
										<div class="or-seperator">
											<i>or</i>
										</div>
 									-->
								</form>
								<p class="text-center text-muted small">
									<spring:message
											code="member.join.text"></spring:message>
									<a href="${ pageContext.request.contextPath }/join"><spring:message
											code="member.join"></spring:message></a>
								</p>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
		<!-- End Login Section -->
	</div>

	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>
	<!-- End Footer -->

</body>
</html>