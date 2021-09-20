<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
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
<script>
var string = ${ memberVO.contact }

var tel1 = string.substring(0,2)
var tel2 = string.substring(3,5)
var tel3 = string.substring(6,8)
</script>
</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- main -->
	<div id="wrapper">
		<!-- ======= Mypage Section ======= -->
		<section id="mypage" class="container">
			<div class="row">
				<div class="col-sm-12 mb-5">
					<h2 class="page-title">
						<spring:message code="member.mypage"></spring:message>
					</h2>
					<p class="card-text">
						<spring:message code="member.mypage.text"></spring:message>
					</p>
				</div>
				<div class="container">
					<div class="row justify-content-center">
						<div class="col-lg-6 d-flex align-items-center">
							<table class="table">
								<tr>
									<th><strong>아이디</strong></th>
									<td>${ memberVO.id }</td>
								</tr>

								<tr>
									<th><strong>이름</strong></th>
									<td>${ memberVO.name }</td>
								</tr>
								<tr>
									<th><strong>연락처</strong></th>
<%-- 									<td>${ memberVO.contact }</td> --%>
										<td>010 - 3627 - 1930</td>
								</tr>
								<tr>
									<th><strong>이메일</strong></th>
									<td>${ memberVO.emailId }@${ memberVO.emailDomain }</td>
								</tr>
								<tr>
									<th><strong>주소</strong></th>
									<td>${ memberVO.addr1 }<br>${ memberVO.addr2 }</td>
								</tr>
								<tr>
									<th><strong>회원 인증여부</strong></th>
									<td><c:choose>
											<c:when test='${ memberVO.type } == 1'>
												<span>인증 완료</span>
											</c:when>
											<c:when test='${ memberVO.type } == 1'>
												<span>관리자</span>
											</c:when>
											<c:otherwise>
												<span style="color: red">미인증</span>
												<button class="btn btn-info" onclick="btnClick('c')">인증하기</button>
											</c:otherwise>
										</c:choose></td>
								</tr>
								<tr>
							</table>
						</div>
						<!-- 					<section id="bottomBtns" class="bottomBtns">
						<div class="container">
							<div class="row justify-content-center">
								<div class="col-md-8">
									<button class="btn btn-primary" onclick="btnClick('m')">
										내 정보 수정</button>
								</div>
							</div>
						</div>
					</section>
 -->
					</div>
				</div>
			</div>
		</section>
	</div>


	<!-- End Join Section -->
	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>

	<!-- End Footer -->

	<script>
		function btnClick(btnType) {
			switch (btnType) {
			case 'c':
				location.href = '${ pageContext.request.contextPath }/certify';
				break;
			case 'm':
				location.href = '${ pageContext.request.contextPath }/member/modify';
				break;
			}
		}
	</script>
</body>
</html>