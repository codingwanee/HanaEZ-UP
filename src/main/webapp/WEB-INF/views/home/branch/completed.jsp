<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
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
	<div id="wrapper pt-5">
		<!-- ---Branch searching section--- -->
		<section id="reservation-completed"
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
											<div class="col-sm-10">
												<div
													class="row col-lg-12 align-items-center justify-content-center">
													<div class="section-title" data-aos="fade-up">
														<h2>${reservVO.member}님의 예약신청이 성공적으로 완료되었습니다.</h2>
														<p></p>
													</div>
												</div>
											<div class="row d-flex justify-content-center input-group">
												<p class="mb-5">예약 내용은 보내드린 이메일 또는 문자에서도 확인하실 수 있습니다.</p>
												<div class="list-group mb-5 shadow">
													<div class="list-group-item">
														<div class="row align-items-center">
															<div class="col">
																<strong class="mb-2">예약지점</strong>
															</div>
															<div class="col-auto">
																<p class="text-muted mb-0">${reservVO.branch}</p>
															</div>
														</div>
													</div>
													<div class="list-group-item">
														<div class="row align-items-center">
															<div class="col">
																<strong class="mb-2">예약날짜</strong>
															</div>
															<div class="col-auto">
																<p class="text-muted mb-0">${reservVO.resDate}</p>
															</div>
														</div>
													</div>
													<div class="list-group-item">
														<div class="row align-items-center">
															<div class="col">
																<strong class="mb-2">예약시간</strong>
															</div>
															<div class="col-auto">
																<p class="text-muted mb-0">${reservVO.resTime}</p>
															</div>
														</div>
													</div>
													<div class="list-group-item">
														<div class="row align-items-center">
															<div class="col">
																<strong class="mb-2">희망 서비스</strong>
															</div>
															<div class="col-auto">
																<p class="text-muted mb-0">${reservVO.service}</p>
															</div>
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
			</div></div>
		</section>
	</div>

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>