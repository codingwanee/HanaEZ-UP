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

<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<!-- common css -->
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />


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
						<spring:message code="branch.search.title"></spring:message>
					</h2>
					<p class="card-text">
						<spring:message code="branch.search.text"></spring:message>
					</p>
					<div class="row align-items-center justify-content-center">
						<div class="col-md-12 align-items-center">
							<div class="card shadow">
								<div class="card-body">
									<div class="container">
										<div class="row">
											<div class="col-sm-12">
												<div class="form-row">
													<form class="form-inline">
														<div class="form-group">
															<div class="input-group">
																<input type="text" class="form-control" id="keyword"
																	placeholder="Searching keyword...">
															</div>
															<!-- /input-group -->
														</div>
														<span class="input-group-btn"><button
																class="btn btn-default" type="button"
																onclick="javascript:getResults(); return false;">Search</button>
														</span>
													</form>
												</div>
											</div>
										</div>
										<!-- /.col-lg-6 -->
										<div class="row">
											<hr>
											<div class="col-md-6 branch-search-input align-items-center">
												<div class="col-md-12 branch-search-result">
													<p class="card-text">해당 지점을 클릭하시면 오른쪽에 위치가 표시됩니다.</p>
													<div id="brSearch-result" class="col-md-12 p-0"></div>
													<!-- simple table -->
												</div>
											</div>
											<div class="col-md-6 align-items-center">
												<div class="brMap">
													<!-- 하단 지도표시 부분 -->
													<div id="branchMap" style="width: 400px; height: 350px;"></div>
												</div>
												<div
													class="row col-md-12 align-items-center justify-content-center">
													<div id="branchFooter">
														<button type="button" class="btn btn-outline-info"
															data-toggle="modal" data-target="#sundayBranch">선택지점
															이용예약</button>
														<!-- <button onclick="sendBranch()" class="btn btn-info">선택지점 이용예약</button> -->
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>

	<script type="text/javascript"
		src="//dapi.kakao.com/v2/maps/sdk.js?appkey=<spring:eval expression="@property['kakaoJavaScriptKey']"></spring:eval>&libraries=services"></script>

	<script>
		var mapContainer = document.getElementById('branchMap'), // 지도를 표시할 div 
		mapOption = {
			center : new kakao.maps.LatLng(35.233562, 128.881305), // 지도의 중심좌표
			level : 3, // 지도의 확대 레벨
			mapTypeId : kakao.maps.MapTypeId.ROADMAP
		// 지도종류
		};

		// 지도를 생성한다 
		var map = new kakao.maps.Map(mapContainer, mapOption);

		// 지도에 확대 축소 컨트롤을 생성한다
		var zoomControl = new kakao.maps.ZoomControl();

		// 지도의 우측에 확대 축소 컨트롤을 추가한다
		map.addControl(zoomControl, kakao.maps.ControlPosition.RIGHT);

		// 목록에서 지점을 선택하면 해당 지점으로 좌표를 이동하고 마커, 정보를 표시해준다.
		// kakao map :: 좌표 이동시키기
		function setCenter(lat, lon) {

			// 마커가 표시될 위치입니다 
			var markerPosition = new kakao.maps.LatLng(lat, lon);

			// 받아 온 위도, 경도로 지도중심 이동	    
			map.setCenter(new kakao.maps.LatLng(lat, lon));

			// 마커를 생성합니다
			var marker = new kakao.maps.Marker({
				position : markerPosition
			});

			// 마커가 지도 위에 표시되도록 설정합니다
			marker.setMap(map);

			/* 			
			 인포윈도우에 표출될 내용으로 HTML 문자열이나 document element가 가능합니다
			var iwContent = '<div id="locBox" style="padding:2px;">'
			iwContent += '</div>'
			iwContent += ''

			iwPosition = new kakao.maps.LatLng(lat, lon); //인포윈도우 표시 위치입니다

			// 인포윈도우를 생성합니다
			var infowindow = new kakao.maps.InfoWindow({
				position : iwPosition,
				content : iwContent
			}); 

			// 마커 위에 인포윈도우를 표시합니다. 두번째 파라미터인 marker를 넣어주지 않으면 지도 위에 표시됩니다
			infowindow.open(map, marker);
			 */

			// 선택지점 셋팅
		}
	</script>
	<script>
		var branch = '';

		function getResults() {
			let keyword = $("#keyword").val();
			$.ajax({
				url : '${ pageContext.request.contextPath }/branch/search/'
						+ keyword,
				type : 'get',
				success : function(data) {
					$('#brSearch-result').empty();
					let list = JSON.parse(data);

					if (data == null) {
						let str = 'No results for ' + keyword
								+ '. Please check keyword again.';
						$('#brSearch-result').append(str);
					} else {
						$(list).each(
								function() {
									/* let bid = "a" + this.bid; */

									let str = '';
									str += '<hr>';
									str += '<div id="' + this.bid
											+ '" class="branch"'
									str += 'onclick="javascript:setCenter('
											+ this.loc + '); return false;">';
									str += '<strong>' + this.nameKo + ' / '
											+ this.nameEn + '</strong>';
									str += '<br>' + this.addrKoOld + '<br>'
											+ this.addrEn
									str += '</div>'

									$('#brSearch-result').append(str);
								})
					}
				},
				error : function() {
					$('#brSearch-result').empty();
					let str = '검색 결과가 없습니다.';
					$('#brSearch-result').append(str);
				}
			})
		}

		//js		
		$(document).on('click', '.branch', function() {
			branch = $(this).attr('id');
		});
		/*
		 function setBranch(bid) {
		 console.log(bid)
		 branch = bid;
		 }

		
		 function selectBranch(lat, lon) {
		 setCenter(lat, lon)
		 //		setBranch(bid)
		 }
		 */

		function sendBranch() {
			location.href = "${ pageContext.request.contextPath }/branch/reserv/"
					+ branch
		}
	</script>
	<jsp:include page="/WEB-INF/views/home/branch/sundayBranches.jsp" />

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>