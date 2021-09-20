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

												<form
													action="${ pageContext.request.contextPath }/authmail/sending"
													method="post">

													이메일 : <input type="email" name="mail"
														placeholder="  이메일주소를 입력하세요. ">
													<button type="submit" name="submit">이메일 인증받기 (이메일
														보내기)</button>

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
	
		<a href="#authmail" data-toggle="modal">
			<button class="btn btn-info">Email Modal</button>
		</a>
		<div class="modal fade" id="authmail">
			<div class="modal-dialog">
				<div class="modal-content">
					<!-- header -->
					<div class="modal-header">
						<!-- header title -->
						<h4 class="modal-title"><spring:message code="mail.modal.title"></spring:message></h4>
						<!-- 닫기(x) 버튼 -->
						<button type="button" class="close" data-dismiss="modal">×</button>
					</div>
					<!-- body -->
					<div class="modal-body">
						<div class="container">
							<div class="row d-flex justify-content-center">
								<div class="col-sm-8">
									<form
										action="${ pageContext.request.contextPath }/authmail/sending"
										method="post">
										이메일을 입력하세요. 이메일 : <input type="email" name="mail"
											placeholder="이메일주소를 입력하세요.">
										<button type="submit" name="submit">이메일 인증받기 (이메일
											보내기)</button>
									</form>
								</div>
							</div>

							<a href="#email-val-completed" data-dismiss="modal" data-toggle="modal">
								<button>Email completed</button>
							</a>
						</div>
						<!-- /.row -->
					</div>
					<!-- /.container -->
				</div>
				<!-- Footer -->
				<div class="modal-footer">
					<button type="button" class="btn btn-default" data-dismiss="modal">닫기
					</button>
				</div>
			</div>
		</div>

	<div class="modal fade" id="email-val-completed">
		<div class="modal-dialog">
			<div class="modal-content">
				<!-- header -->
				<div class="modal-header">
					<!-- header title -->
					<h4 class="modal-title"><spring:message code="mail.modal.successtitle"></spring:message></h4>
					<!-- 닫기(x) 버튼 -->
					<button type="button" class="close" data-dismiss="modal">×</button>
				</div>
				<!-- body -->
				<div class="modal-body">
					<div class="container">

						<div class="row align-items-center h-100">
							<form class="col-lg-12 col-md-12 col-10 mx-auto text-center">
								<div class="mx-auto text-center my-4">
									<h4 class="my-3">
										<spring:message code="mail.modal.successmsg"></spring:message>
									</h4>
								</div>
								<div class="alert alert-success" role="alert">
									<spring:message code="mail.modal.successtext"></spring:message>
								</div>
							</form>
							<button type="button" class="btn btn-lg btn-secondary btn-block"
								data-dismiss="modal" onclick="location.href='${ pageContext.request.contextPath }/certify'">
								<spring:message code="mail.modal.closebtn"></spring:message></button>
							<p class="mt-5 mb-3 text-muted">© Hyewon Jeon</p>
						</div>
					</div>
					<!-- /.row -->
				</div>
				<!-- /.container -->
			</div>
			<!-- Footer -->
			<div class="modal-footer">
				<button type="button" class="btn btn-default" data-dismiss="modal">닫기
				</button>
			</div>
		</div>
	</div>
	



	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>
	<!-- End Footer -->
</body>

</html>