<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!doctype html>
<html>
<head>
<!-- ======= Head ======= -->
<title>HanaEZ UP Admin Side</title>
<!-- Favicons -->
<link href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png" rel="icon">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<style>
.circle {
	background-color: #00aaaa;
	border-radius: 4px;
	width: 8px;
	height: 8px;
}
</style>
</head>
<body class="vertical  light  ">
	<div class="wrapper">

		<!-- ======= Aside Menubar ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />
		<!-- Aside Menubar -->

		<main role="main" class="main-content">
			<div class="container-fluid">
				<div class="row">
					<div class="col-12">
						<h2 class="mb-5">Main</h2>
						<!-- 						<h2 class="mb-5" style="color:#00aaaa; font-family:hanaM;">손님의 기쁨, 그 하나를 위하여</h2> -->
					</div>
					<div class="row m-5 align-items-center">
						<div class="col-md-12">
							<img
								src="${ pageContext.request.contextPath }/resources/images/bank building.png"
								style="width: 800px;">
						</div>
					</div>
					<div class="col-md-12">
						<div class="row align-items-center">
							<div class="col-md-7">
								<h4 class="mb-1">[${ employeeVO.ename }] 행원님, 오늘도 좋은 하루
									되세요.</h4>
							</div>
						</div>
						<div class="row mb-4">
							<div class="col-md-7">
								<p class="text">
								<table class="table">
									<tr>
										<th><span class="circle"></span> 행원번호</th>
										<td>${ employeeVO.eid } <span class="badge badge-dark">
												계장 </span>
										</td>
										<th><span class="circle"></span> 메일주소</th>
										<td>easyone@hanafn.com</td>
									</tr>
									<tr>
										<th><span class="circle"></span> 근무지점</th>
										<td>외국인관리부</td>
										<th><span class="circle"></span> 내선번호</th>
										<td>382</td>
									</tr>
								</table>
								</p>
							</div>
						</div>
					</div>
				</div>
			</div>
		</main>



	</div>
	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- End Footer -->
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>