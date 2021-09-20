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

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<link href="http://www.jqueryscript.net/css/jquerysctipttop.css"
	rel="stylesheet" type="text/css">
<link
	href="${ pageContext.request.contextPath }/resources/css/jquery-nicelabel.css"
	rel="stylesheet">

</head>
<body>

	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />



	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="branch-search"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title">
						<spring:message code="branch.title"></spring:message>
					</h2>
					<p class="card-text">
						<spring:message code="branch.text"></spring:message>
					</p>
					<div class="row align-items-center justify-content-center">
						<div class="col-md-12 align-items-center">
							<div class="card shadow">
								<div class="card-body">
									<div class="container">
										<div class="row ">
											<div class="col-sm-6">

												<form method="post"
													action="${ pageContext.request.contextPath }/branch/reserv"
													name="reservForm" onsubmit="return checkReserv()">
													<input type="text" value="${branchVO.bid}" name="branch"
														hidden="hidden" />
													<div
														class="col-md-12 align-items-center justify-content-center hanaUL">
														<div class="form-group row-md-12 ">
															<p class="mb-2">
																<strong><spring:message code="branch.branch"></spring:message></strong>
															</p>
															<label for="example-date"><spring:message
																	code="branch.checkbranch"></spring:message></label>
															<div class="input-group">
																<input type="text"
																	placeholder="${branchVO.nameKo} / ${branchVO.nameEn}"
																	name="branch" class="form-control" disabled />
															</div>
														</div>
														<div class="form-group row-md-12">
															<p class="mb-2">
																<strong><spring:message code="date"></spring:message>
																	& <spring:message code="time"></spring:message> </strong>
															</p>
															<label for="example-date"><spring:message
																	code="branch.pickdate"></spring:message></label> <input
																required class="form-control" id="resDate" type="date"
																name="resDate" />
														</div>
														<div class="form-group row-md-12">
															<label for="time-input2"><spring:message
																	code="branch.picktime"></spring:message></label>
															<div class="input-group"></div>
															<!-- 
										<div id="text-radio">
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "09:00", "unchecked_text": "09:00"}' checked type="radio" name="text_radio" />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "10:30", "unchecked_text": "10:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "11:00", "unchecked_text": "11:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "11:30", "unchecked_text": "11:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "12:00", "unchecked_text": "12:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "12:30", "unchecked_text": "12:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "12:00", "unchecked_text": "12:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "12:30", "unchecked_text": "12:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "13:00", "unchecked_text": "13:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "13:30", "unchecked_text": "13:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "14:00", "unchecked_text": "14:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "14:30", "unchecked_text": "14:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "15:00", "unchecked_text": "15:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "15:30", "unchecked_text": "15:30"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "16:00", "unchecked_text": "16:00"}' type="radio" name="text_radio"  />	
											<input class="text-nicelabel" data-nicelabel='{"position_class": "text_radio", "checked_text": "16:30", "unchecked_text": "16:30"}' type="radio" name="text_radio"  />			
										</div>										
										 -->
													<div class="select-time">
														<select class="form-control" id="example-select"
															name="resTime" required>
															<option value="10:00">10:00</option>
															<option value="10:30">10:30</option>
															<option value="10:00">11:00</option>
															<option value="10:30">11:30</option>
															<option value="10:00">12:00</option>
															<option value="10:30">12:30</option>
															<option value="10:00">13:00</option>
															<option value="10:30">13:30</option>
															<option value="10:00">14:00</option>
															<option value="10:30">14:30</option>
															<option value="10:00">15:00</option>
															<option value="10:30">15:30</option>
														</select>
													</div>
												</div>
														<p class="mb-2">
															<strong><spring:message code="branch.service"></spring:message></strong>
														</p>
														<div class="form-row">
															<div class="form-group col-md-12">
																<label for="simple-select2"><spring:message
																		code="branch.pickservice"></spring:message></label> <select
																	name="service" class="form-control select2 hanaUL"
																	id="simple-select2" style="font-family: hanaUL">
																	<optgroup label="신규 손님">
																		<option value="신규계좌"><spring:message
																				code="service.openaccount"></spring:message></option>
																		<option value="본인인증"><spring:message
																				code="service.certification"></spring:message></option>
																	</optgroup>
																	<optgroup label="기존 손님">
																		<option value="환전"><spring:message
																				code="service.transfer"></spring:message></option>
																		<option value="해외송금"><spring:message
																				code="service.remittance"></spring:message></option>
																		<option value="대출"><spring:message
																				code="service.loan"></spring:message></option>
																	</optgroup>
																	<optgroup label="그 외">
																		<option value="ETC">ETC</option>
																	</optgroup>
																</select>
															</div>
														</div>
														<div class="row justify-content-center align-items-center">
															<button type="submit" class="btn btn-info">
																<spring:message code="branch.register"></spring:message>
															</button>
														</div>
													</div>
												</form>
											</div>
											<!-- 
											<div class="col-sm-6 info01">

												Please read carefully before visiting a branch. <br>
												<br>The bank operates 19 branches
												that remain open on <strong>Sundays from
													10 a.m. to 4 p.m.</strong>. They
												provide services for making overseas remittances, exchanging
												foreign currency, issuing and re-issuing check cards,
												opening/closing bank accounts, and other vital banking
												matters. Please note that many but <strong>not
													all banking transactions </strong>are
												supported at Sunday Banking. <br>											
												
												 <br>Notes: <br>1.
												<strong>To easily locate our Sunday
													Banking locations </strong>and any other branches &amp; ATMs in our
												global network, please visit our English-language Branch
												Locator on our website: <a
													href="https://l.facebook.com/l.php?u=https%3A%2F%2Fwww.kebhana.com%2F&amp;h=AT3wrD6Q7xE3ldzok8kuMY1DbNLyx76S_qTer8g1vCziP1_KCKEbjEzWYH3MQht8USzAVad0k2RpdVcx6IZpYyf1KepUS_2wG4h4TLRqiNMNGCZy-5MoimaF2T3UWyP7XF-N7341ONe789S5XR-nBA"
													target="_blank" rel="noopener nofollow"
													data-lynx-mode="asynclazy">https://www.kebhana.com</a> <strong>&gt; User Guide &gt; Branches &gt;
													Expatriate &gt; Sunday Banking &gt; Search <br>
												</strong><br>2. Also visit <a
													href="https://l.facebook.com/l.php?u=http%3A%2F%2Fopenhanafn.tritops.co.kr%2Fcontent_en.jsp&amp;h=AT29FBjnSsY7vJ7Q5UnQDdc20eNSH0BXgT7OZL36eHdpAMaePTNhrMR6u7Ik5BRZCD4lPsECvS7FgDNjGGtEouuFopCRCzTJkWdZ6vIvwbz9xpQfAewI03Y7WNYH08-Y0rOfTihFknVrxU5C3CduJQ"
													target="_blank" rel="noopener nofollow"
													data-lynx-mode="asynclazy">http://openhanafn.tritops.co.kr/content_en.jsp</a>
												<strong>&gt; Expatriates &gt; Sunday
													Banking<br> <br>
												</strong>3. You may also use mapping apps such as <strong>Google
													Maps </strong>and <strong>English Naver/Daum Maps
												</strong>to locate our branches by entering their address on the
												search bars. <br> <br>
											</div>
											 -->
											<!--
											<div class="col-sm-6 info01 p-5">
											<h5 class="mb-3">하나은행 외국인 근로자 특화지점 안내</h5>
											<ul style="list-style-type:square;">
												<li>외국인 근로자 특화지점은 일요일 10:00 부터 16:00까지 운영됩니다. 따라서 지점 이용 예약은 15:30 까지 가능합니다.</li>
												<li>해외송금, 환전, 카드 재발급, 계좌 개설/해지 등이 가능합니다. 모든 은행업무가 가능하지는 않을 수도 있음에 유의해주세요.</li>
												<li>전국에 운영중인 하나은행 외국인 근로자 특화지점 전체목록을 확인하시려면 <a href="#"><span style="font-weight: bold">여기</span></a>를 눌러주세요.</li>
											</ul>
 										<ul style="list-style-type:square;">
											<li>Sunday branches open <strong> from 10 a.m. to 4 p.m.</strong>. Reservations can be made until 15:30.</li>
											<li>19 Sunday Banking locations nationwide for customers who need service on weekends</li>												
											<li>It provides services for making overseas remittances, exchanging
												foreign currency, issuing and re-issuing check cards,
												opening/closing bank accounts, and other vital banking
												matters. Please note that many but <strong>not
													all banking transactions </strong>are
												supported at Sunday Banking. <br>	</li> 
											</ul>
											</div>
											-->
											<div class="col-sm-6 p-5">
											<img src="${ pageContext.request.contextPath }/resources/assets/img/schedule-img.svg" class="img-fluid w-100">
										</div>
										</div>
										<!-- /.card-body -->
									</div>
									<!-- /.card -->
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>
	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->

	<script>
		$('.time-input').timepicker({
			'scrollDefault' : 'now',
			'zindex' : '9999' /* fix modal open */
		});

		var start = moment().subtract(29, 'days');
		var end = moment();

		// Example starter JavaScript for disabling form submissions if there are invalid fields
		(function() {
			'use strict';
			window.addEventListener('load',
					function() {
						// Fetch all the forms we want to apply custom Bootstrap validation styles to
						var forms = document
								.getElementsByClassName('needs-validation');
						// Loop over them and prevent submission
						var validation = Array.prototype.filter.call(forms,
								function(form) {
									form.addEventListener('submit', function(
											event) {
										if (form.checkValidity() === false) {
											event.preventDefault();
											event.stopPropagation();
										}
										form.classList.add('was-validated');
									}, false);
								});
					}, false);
		})();
	</script>
	<script
		src="${ pageContext.request.contextPath }/resources/assets/js/jquery.nicelabel.js"></script>
	<script>
		function checkReserv() {

			let form = document.reservForm;

			if (isNull(form.resDate, '날짜를 선택해주세요.'))
				return false;
			/*
			if(.value == )
			if(form.resTime) */

			return true;
		}
	</script>
	<script>
		$(function() {
			$('#text-radio > input').nicelabel();
		});
	</script>
</body>
</html>