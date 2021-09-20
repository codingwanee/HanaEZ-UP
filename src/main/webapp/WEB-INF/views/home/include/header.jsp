<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<style>
.language>li {
	font-family: sans-serif;
}

#time-out {
	width: 80px;
	height: 30px;
	color: #fff;
	background-color: #007576;
	border-radius: 50px;
	padding: 0 16px;
	font-size: 1.3em;
	font-family: hanaM;
}

#session-box {
	/*     display: inline-block; */
	border-radius: 50px;
	width: 120px;
	height: 30px;
	border: 1px solid #dadcdb;
}

#session-out a {
	width: 20px;
}
</style>

<header id="header" class="fixed-top">
	<div class="container-fluid d-flex">
		<%--<div class="logo mr-auto">
				 <h1 class="text-light">
					<a href="${ pageContext.request.contextPath }/">
					<span style="margin-left: 70px;" >HanaEZ Up</span></a>
				</h1> 
			</div>--%>
		<!-- Uncomment below if you prefer to use an image logo -->
		<div class="logo mr-auto">
			<a href="${ pageContext.request.contextPath }/"> <img
				src="${ pageContext.request.contextPath }/resources/images/hanaez-logo.png"
				alt="" class="img-fluid">
			</a>
		</div>
		<nav class="nav-menu d-none d-lg-block">
			<ul>
				<li><c:if test="${ not empty loginVO }">
						<div id="session-out">
							<div id="session-box">
								<span id="time-out"></span><a href="#"><span
									id="session-extend">연장</span></a>
							</div>
						</div>
					</c:if></li>
				<li class="active"><a
					href="${ pageContext.request.contextPath }/fakelogin">Home</a></li>
				<li class="drop-down"><a href="#"><spring:message
							code="menu.banking"></spring:message></a>
					<ul>
						<li><a href="${ pageContext.request.contextPath }/">계좌조회</a></li>
						<li><a href="${ pageContext.request.contextPath }/">계좌이체</a></li>
						<li><a href="${ pageContext.request.contextPath }/">외국인
								대출</a></li>
						<li><a
							href="${ pageContext.request.contextPath }/exchangeRate">환전</a></li>
						<li><a href="${ pageContext.request.contextPath }/">해외송금</a></li>
					</ul>
				<li class="drop-down"><a href="#"><spring:message
							code="menu.product"></spring:message></a>
					<ul>
						<li><a
							href="${ pageContext.request.contextPath }/account/easyone">Easy
								One 예적금</a></li>
						<li><a href="${ pageContext.request.contextPath }/cards">카드
								상품</a></li>
						<li><a
							href="${ pageContext.request.contextPath }/account/easyone">기타
								금융상품</a></li>
					</ul></li>
				<li class="drop-down"><a href="#"><spring:message
							code="menu.useful"></spring:message></a>
					<ul>
						<li><a href="${ pageContext.request.contextPath }/certify"><spring:message
									code="menu.certify"></spring:message></a></li>
						<li><a href="${ pageContext.request.contextPath }/branch"><spring:message
									code="menu.branch"></spring:message></a></li>
						<li><a href="${ pageContext.request.contextPath }/board"><spring:message
									code="menu.board"></spring:message></a></li>
						<li><a href="${ pageContext.request.contextPath }/translator"><spring:message
									code="menu.cs.translator"></spring:message></a></li>
						<li><a
							href="${ pageContext.request.contextPath }/foreignerService">Foreigner
								Service</a></li>
					</ul></li>
				<!-- 언어선택 메뉴 -->
				<li class="drop-down"><a href="#">Language</a>
					<ul class="language">
						<%-- 						<li style="font-family:sans-serif;"><a href="<c:url value='/i18n?lang=ko' />">한국어</a></li>
							<li style="font-family:sans-serif;"><a href="<c:url value='/i18n?lang=en' />">English</a></li>
							<li style="font-family:sans-serif;"><a href="<c:url value='/i18n?lang=th' />">ประเทศไทย</a></li> --%>
						<li><a href="javascript:locale('ko')">한국어</a></li>
						<li><a href="javascript:locale('en')">English</a></li>
						<li><a href="javascript:locale('th')">ประเทศไทย</a></li>
						<li><a href="javascript:locale('th')">中文</a></li>
						<li><a href="javascript:locale('th')">සිංගලා</a></li>
						<li><a href="javascript:locale('th')">Myanmar</a></li>
						<li><a href="javascript:locale('th')">Việt nam</a></li>
						<li><a href="javascript:locale('th')">Pilipinas</a></li>
						<li><a href="javascript:locale('th')">नेपाल</a></li>
						<li><a href="javascript:locale('th')">Indonesia</a></li>
						<li><a href="javascript:locale('th')">Cambodian</a></li>
						<li><a href="javascript:locale('th')">日本語</a></li>
						<li><a href="javascript:locale('th')">Монгол</a></li>
						<li><a href="javascript:locale('th')">កម្ពុជា</a></li>
						<li><a href="javascript:locale('th')">Россия</a></li>
						<li><a href="javascript:locale('th')">O'zbekiston</a></li>
					</ul></li>
				<%-- 				<li><a href="#localeModal" data-toggle="modal"><spring:message code="menu.locale"></spring:message></a></li> --%>
				<li><c:choose>
						<c:when test="${ empty loginVO }">
							<a href="${ pageContext.request.contextPath }/join"><spring:message
									code="member.join"></spring:message></a>
						</c:when>
						<c:when test="${ loginVO.type eq '9' }">
							<a href="${ pageContext.request.contextPath }/admin">관리자페이지</a>
						</c:when>
						<c:otherwise>
							<a href="${ pageContext.request.contextPath }/mypage"><spring:message
									code="member.mypage"></spring:message></a>
						</c:otherwise>
					</c:choose></li>
				<li class="get-started"><c:choose>
						<c:when test="${ empty loginVO }">
							<a href="${ pageContext.request.contextPath }/login"> <spring:message
									code="member.login"></spring:message></a>
						</c:when>
						<c:otherwise>
							<a href="${ pageContext.request.contextPath }/logout"> <spring:message
									code="member.logout"></spring:message></a>
						</c:otherwise>
					</c:choose></li>
			</ul>
		</nav>
	</div>
</header>
<br />
<div class="modal fade" id="localeModal">
	<div class="modal-dialog">
		<div class="modal-content">
			<!-- header -->
			<div class="modal-header">
				<!-- header title -->
				<h4 class="modal-title">Choose your Language</h4>
				<!-- 닫기(x) 버튼 -->
				<button type="button" class="close" data-dismiss="modal">×</button>
			</div>
			<!-- body -->
			<div class="modal-body">
				<div class="container">
					<div class="row">
						<div class="col-sm-3">
							<div class="row locale">
								<a href="<c:url value='/i18n?lang=ko' />">Korean<br>한국어
								</a>
							</div>
							<div class="row locale">
								Sri Lankan<br>සිංගලා
							</div>
							<div class="row locale">Mongolian</div>
							<div class="row locale">
								Bangladeshi<br>नेपाल
							</div>
						</div>
						<!-- /.col-sm-3 -->
						<div class="col-sm-3">
							<div class="row locale">
								<a href="<c:url value='/i18n?lang=en' />">English<br>English
								</a>
							</div>
							<div class="row locale">Myanmar</div>
							<div class="row locale">Indonesia</div>
							<div class="row locale">
								Nepali<br>កម្ពុជា
							</div>
						</div>
						<!-- /.col-sm-3 -->
						<div class="col-sm-3">
							<div class="row locale">
								<a href="<c:url value='/i18n?lang=th' />">Thai<br>ประเทศไทย
								</a>
							</div>
							<div class="row locale">
								Vietnamese<br>Người việt nam
							</div>
							<div class="row locale">Cambodian</div>
							<div class="row locale">
								Russian<br>Россия
							</div>
						</div>
						<!-- /.col-sm-3 -->
						<div class="col-sm-3">
							<div class="row locale">
								Chinese<br>中文
							</div>
							<div class="row locale">
								Filipino<br>Pilipinas
							</div>
							<div class="row locale">
								Japanese<br>日本語
							</div>
							<div class="row locale">
								Uzbek<br>O'zbekiston
							</div>
						</div>
						<!-- /.col-sm-3 -->
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
</div>

<div class="modal fade" id="sessionModal" tabindex="-1" role="dialog"
	aria-labelledby="exampleModalLongTitle" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title" id="exampleModalLongTitle">자동 로그아웃 안내</h5>
				<button type="button" class="close" data-dismiss="modal"
					aria-label="Close">
					<span aria-hidden="true">&times;</span>
				</button>
			</div>
			<div class="modal-body p-4">
			
			<div class="row col-md-10">
 			<p class="mb-3">자동 로그아웃 남은시간 : <span id="time-out"></span></p>
			<p class="mb-3">
			<br>로그인 후 약 10분 동안 서비스 이용이 없어
			<br>고객님의 안전한 금융거래를 위하여
			<br>자동 로그아웃 될 예정입니다.
			<br>
			<br>로그인 시간을 연장하시겠습니까?</p>
			</div>
			<div class="row col-md-10">
			<a href="#"><button id="session-extend" class="btn btn-primary"  data-dismiss="modal">연장하기</button></a>
			<a href="${ pageContext.request.contextPath }/logout"><button class="btn btn-outline-secondary">로그아웃</button></a>
			</div>
			
			</div>
		</div>
	</div>
</div>

<script>
	function locale(lang) {
		var callLocale = '${ pageContext.request.contextPath }/i18n?lang='+ lang;
		$.ajax({
			url : callLocale,
			type : 'get',
			success : function(data) {
				location.reload();
			},
			error : function() {
				alert('알 수 없는 에러가 발생했습니다.');
			}
		})
	}
</script>

<script type='text/javascript'>
	var minutes = 10;
	var seconds = 00;
	$(document).ready(function() {
		function calculate() {
			setTimeout(calculate, 1000);
			$('#time-out').html(minutes + ' : ' + seconds);
			seconds--;
			if (minutes == 1 && seconds == 0) {
				$("#sessionModal").modal("show");
			}

			if (seconds < 0) {
				seconds = 59;
				minutes--;
				if (minutes < 0) {
					minutes = 0;
					seconds = 0;
					location.href = "${ pageContext.request.contextPath }/logout";
					alert("시간이 만료되어 자동으로 로그아웃 되었습니다.\n다시 로그인해주세요.");
				}
			}
		}
		calculate();
	});

	$(document).ready(function() {
		$('#session-extend').click(function() {
			minutes = 10;
			seconds = 00;
		})
	})
</script>
