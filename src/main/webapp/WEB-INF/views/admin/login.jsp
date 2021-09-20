<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<!-- ======= Head ======= -->
<title>HanaEZ UP Admin Side</title>
<!-- Favicons -->
<link href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png" rel="icon">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<link rel="stylesheet" type="text/css"
	href="${ pageContext.request.contextPath }/resources/css/admin.css">

</head>
<body>

	<div class="container justify-content-center align-items-center mt-5">
		<div class="row justify-content-center align-items-center mt-5">
			<div class="col-lg-6 col-md-8 login-box">
				<div class="col-lg-12 login-title mt-5">
					HanaEZ-UP<br>ADMIN PANEL</div>
				<div class="col-lg-12 login-form justify-content-center align-items-center">
					<div class="col-lg-12 login-form justify-content-center align-items-center">
						<form action="${ pageContext.request.contextPath }/admin/login"
							method="post" name="login">							

							<div class="form-group">
								<input type="text" class="form-control hanaUL" name="eid" placeholder="행원번호">
							</div>
							<div class="form-group">
								<input type="password" class="form-control hanaUL" name="password" placeholder="비밀번호">
							</div>
							<div class="row justify-content-center align-items-center">
								<div class="login-button">
									<button type="submit" style="width: 150px"class="btn btn-login hanaUL">로그인</button>
								</div>
							</div>
						</form>
					</div>
				</div>
			</div>
		</div>
		<div class="row justify-content-center align-items-center mt-2">
			<img src="${ pageContext.request.contextPath }/resources/images/logo/login-copyright.png">	
		</div>
	</div>

	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>