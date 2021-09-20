<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!doctype html>
<html>
<head>
<title>HanaEZ UP Admin Side</title>
<!-- Favicons -->

<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>


<!-- ======= Head ======= -->
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />




<!-- Simple bar CSS -->
<link rel="stylesheet"
	href="${ pageContext.request.contextPath }/resources/assets/css/simplebar.css">
<!-- Fonts CSS -->
<link
	href="https://fonts.googleapis.com/css2?family=Overpass:ital,wght@0,100;0,200;0,300;0,400;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,600;1,700;1,800;1,900&display=swap"
	rel="stylesheet">
<!-- Icons CSS -->
<link rel="stylesheet"
	href="${ pageContext.request.contextPath }/resources/assets/css/feather.css">
<!-- Date Range Picker CSS -->
<link rel="stylesheet"
	href="${ pageContext.request.contextPath }/resources/assets/css/daterangepicker.css">



</head>
<body class="vertical  light  ">
	<div class="wrapper">

		<!-- ======= Aside Menubar ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />

		<!-- Aside Menubar -->
		<main role="main" class="main-content">
			<div class="container-fluid">
				<div class="row justify-content-center">
					<div class="col-12">
						<div class="row align-items-center my-4">
							<div class="col">
								<h2 class="h3 mb-0 page-title">지점 이용예약</h2>
							</div>
						</div>

						<!-- Apex Radialbar Charts -->
						<h2 class="h5" id="task-section">
							<script>
								let today = new Date();

								let year = today.getFullYear(); // 년도
								let month = today.getMonth() + 1; // 월
								let date = today.getDate(); // 날짜
								let day = today.getDay(); // 요일

								document.write(year + '/' + month + '/' + date)
							</script>
							일의 예약현황입니다.
						</h2>
						<p class="text-muted">
						<div class="row">
							<div class="col-md-4 my-4">
								<div class="card shadow">
									<div class="card-body text-center">
										<div id="radialbar"></div>
									</div>
									<!-- / .card-body -->
								</div>
								<!-- / .card -->
							</div>
							<!-- /. col -->
							<div class="col-md-4 my-4">
								<div class="card shadow">
									<div class="card-body text-center">
										<div class="col">
											<strong class="card-title">Sparkline Bar</strong>
											<p class="small mb-0">
												<span class="fe fe-12 fe-arrow-up text-success"></span><span
													class="text-muted">37.7%</span>
											</p>
										</div>
										<div class="col-6 text-right">
											<span class="sparkline inlinebar"></span>
										</div>
									</div>
									<!-- / .card-body -->
								</div>
								<!-- / .card -->
							</div>
							<!-- /. col -->
						</div>
						<!-- table -->
						<div class="card shadow">
							<div class="card-body">

								<table class="table table-hover">
									<thead>
										<tr>
											<th>
												<div class="custom-control custom-checkbox">
													<input type="checkbox" class="custom-control-input"
														id="all"> <label class="custom-control-label"
														for="all"></label>
												</div>
											</th>
											<th>예약시간</th>
											<th style="width: 40%">예약자</th>
											<th>예약업무</th>
											<th>상태</th>
											<th>처리</th>
										</tr>
									</thead>
									<tbody>
										<c:forEach items="${ reservationList }" var="reserveVO"
											varStatus="loop">
											<tr>
												<td>
													<div class="custom-control custom-checkbox">
														<input type="checkbox" class="custom-control-input"
															id="${ reserveVO.resId }"> <label
															class="custom-control-label" for="${ reserveVO.resId }"></label>
													</div>
												</td>
												<td><c:choose>
														<c:when test="${ reserveVO.status eq '0'}">
															<p class="mb-0 text-primary">${ reserveVO.resTime }</p>
														</c:when>
														<c:when test="${ reserveVO.status eq '1'}">
															<p class="mb-0 text-muted">${ reserveVO.resTime }</p>
														</c:when>
													</c:choose></td>
												<td><c:choose>
														<c:when test="${ reserveVO.status eq '0'}">
															<p class="mb-0 text-primary">${ reserveVO.member }</p>
														</c:when>
														<c:when test="${ reserveVO.status eq '1'}">
															<p class="mb-0 text-muted">${ reserveVO.member }</p>
														</c:when>
													</c:choose></td>
												<td><c:choose>
														<c:when test="${ reserveVO.status eq '0'}">
															<p class="mb-0 text-primary">${ reserveVO.service }</p>
														</c:when>
														<c:when test="${ reserveVO.status eq '1'}">
															<p class="mb-0 text-muted">${ reserveVO.service }</p>
														</c:when>
													</c:choose></td>
												<c:choose>
													<c:when test="${ reserveVO.status eq '0'}">
														<td class="text-muted"><span
															class="badge badge-pill badge-success">대기중</span></td>
													</c:when>
													<c:when test="${ reserveVO.status eq '1'}">
														<td class="text-muted"><span
															class="badge badge-pill badge-danger">처리완료</span></td>
													</c:when>
													<c:otherwise>
														<td>${ reserveVO.service }</td>
													</c:otherwise>
												</c:choose>

												<td><button
														class="btn btn-sm dropdown-toggle more-horizontal"
														type="button" data-toggle="dropdown" aria-haspopup="true"
														aria-expanded="false">
														<span class="text-muted sr-only">Action</span>
													</button>
													<div class="dropdown-menu dropdown-menu-right">
														<a class="dropdown-item" href="#">처리완료</a> <a
															class="dropdown-item" href="#">노쇼</a>
													</div></td>

											</tr>
										</c:forEach>
									</tbody>
								</table>


							</div>
						</div>
						<nav aria-label="Table Paging" class="my-3">
							<ul class="pagination justify-content-end mb-0">
								<li class="page-item"><a class="page-link" href="#">Previous</a></li>
								<li class="page-item active"><a class="page-link" href="#">1</a></li>
								<li class="page-item"><a class="page-link" href="#">2</a></li>
								<li class="page-item"><a class="page-link" href="#">3</a></li>
								<li class="page-item"><a class="page-link" href="#">Next</a></li>
							</ul>
						</nav>
					</div>
					<!-- .col-12 -->
				</div>
				<!-- .row -->
			</div>
		</main>
		<!-- .container-fluid -->
	</div>



	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- ======= Common JS ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/gauge.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/jquery.sparkline.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/apexcharts.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/apexcharts.custom.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/jquery.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/popper.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/moment.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/bootstrap.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/simplebar.min.js"></script>
	<script
		src='${ pageContext.request.contextPath }/resources/assets/js/daterangepicker.js'></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/config.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/d3.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/topojson.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/datamaps.all.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/datamaps-zoomto.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/datamaps.custom.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/Chart.min.js"></script>
	<script>
		/* defind global options */
		Chart.defaults.global.defaultFontFamily = base.defaultFontFamily;
		Chart.defaults.global.defaultFontColor = colors.mutedColor;
	</script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/gauge.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/jquery.sparkline.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/apexcharts.min.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/apexcharts.custom.js"></script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/apps.js"></script>
	<!-- Global site tag (gtag.js) - Google Analytics -->
	<script async
		src="https://www.googletagmanager.com/gtag/js?id=UA-56159088-1"></script>
	<script>
		window.dataLayer = window.dataLayer || [];

		function gtag() {
			dataLayer.push(arguments);
		}
		gtag('js', new Date());
		gtag('config', 'UA-56159088-1');
	</script>
</body>
</html>