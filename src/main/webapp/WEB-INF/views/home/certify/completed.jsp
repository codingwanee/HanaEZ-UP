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
												<div
													class="row col-lg-12 align-items-center justify-content-center ">
													<div class="section-title" data-aos="fade-up">
														<h2>
															<spring:message code="certify.complete.title"></spring:message>
														</h2>
														<p>
															<spring:message code="certify.complete.text"></spring:message>
														</p>
													</div>
												</div>
												<div class="row d-flex justify-content-center input-group">
													<p class="mb-5">
														<spring:message code="certify.complete.descript"></spring:message>
													</p>
													<div class="list-group mb-5 shadow">
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.certId"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">${certHistoryVO.certId }</p></div>
															</div>
														</div>
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.applicant"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">${certHistoryVO.applicantNm }</p></div>
															</div>
														</div>
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.regDate"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">
																		<script>
																			let today = new Date();

																			let year = today.getFullYear(); // 년도
																			let month = today.getMonth() + 1; // 월
																			let date = today.getDate(); // 날짜
																			let day = today.getDay(); // 요일

																			document.write(year + '/' + month + '/' + date)
																		</script>
																	</p></div>
															</div>
														</div>
													</div>
													<!-- .list-group-item -->
												</div>
												<!-- /input-group -->
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