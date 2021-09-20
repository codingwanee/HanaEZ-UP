<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<!-- ======= Header ======= -->
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
<%--<link href="assets/img/apple-touch-icon.png" rel="apple-touch-icon"> -->
<%-- <link rel="icon" type="image/png" sizes="16x16" href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"> --%>
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />


</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- ======= Main ======= -->
	<div id="wrapper pt-5">
		<!-- ---Branch searching section--- -->
		<section id="certify-completed"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12 pt-5">
					<div class="row align-items-center justify-content-center">
						<div class="col-md-10 align-items-center">
							<div class="card shadow">
								<div class="card-body">
									<div class="container">
										<div class="row d-flex justify-content-center">
											<div class="col-sm-8">

												<form action="${ pageContext.request.contextPath }/authmail/validation/${authCode}" method="post">
													<div>
														인증번호 입력 : <input type="text" name="inputCode"
															placeholder="  인증번호를 입력하세요. ">
													</div>
													<div>
														<button type="submit" name="submit">인증번호 전송</button>
													</div>
												</form>
											</div>
										</div>
										<!-- /.col-lg-6 -->
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>

	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>
	<!-- End Footer -->
</body>
</html>