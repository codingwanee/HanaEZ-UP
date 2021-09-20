<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
	
<!doctype html>
<html>
<head>
<title>HanaEZ UP Admin Side</title>
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<!-- ======= Head ======= -->
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">


<!-- End head -->
</head>
<body class="vertical  light  ">
	<div class="wrapper">

		<!-- ======= Aside Menubar ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />
		<!-- Aside Menubar -->

		<main role="main" class="main-content">
			<div class="container-fluid">
				<div class="row justify-content-center">
					<div class="col-12 col-lg-10 col-xl-8">
						<h2 class="h3 mb-4 page-title">지점등록</h2>
						<div class="my-4">
							<ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
								<li class="nav-item"><a class="nav-link active"
									id="home-tab" data-toggle="tab" href="#home" role="tab"
									aria-controls="home" aria-selected="true">일요 영업점</a></li>
							</ul>
<!-- 
							<div class="form-row mb-4">
								<form class="form-inline">
									<div class="form-group">
										<div class="input-group">
											<input type="text" class="form-control" id="address"
												placeholder="검색할 주소를 입력하세요.">
										</div>
									</div>
									<span class="input-group-btn ml-3"><button
											class="btn btn-primary" type="button" id="find-hanabranch">기존지점 검색</button>
									</span>
									<hr class="my-4">
								</form>
							</div>
 -->
							<form method="post" name="branch"
								action="${ pageContext.request.contextPath }/admin/branch/register">
								<div class="form-row">
								<input id="loc" name="loc" class="form-control" placeholder="" type="hidden">
								<hr class="my-4">								
								<div class="form-group col-md-6">
										<label for="nameKo">지점명(한글)</label> <input type="text"
											name="nameKo" id="nameKo" class="form-control" placeholder=""
											required>
									</div>
									<div class="form-group col-md-6">
										<label for="bid">지점코드</label> <input type="text" id="bid"
											name="bid" class="form-control" placeholder="" required>
									</div>

									<div class="form-group col-md-6">
										<label for="tel">전화번호</label> <input type="text" id="tel"
											name="tel" class="form-control" placeholder="" required>
									</div>
									<div class="form-group col-md-6">
										<label for="fax">팩스번호</label> <input type="text" id="fax"
											name="fax" class="form-control" placeholder="" required>
									</div>
								</div>
								<div class="form-group">
									<label for="nameEn">지점명(영문)</label> <input type="text"
										name="nameEn" class="form-control" id="nameEn"
										placeholder="선택입력">
								</div>

								<hr class="my-4">
								<div class="form-group">
									<label for="addrKoNew">신주소(도로명)</label> <input type="text"
										name="addrKoNew" class="form-control" id="addrKoNew"
										placeholder="" required>
								</div>
								<div class="form-group">
									<label for="addrKoOld">구주소(지번)</label> <input type="text"
										name="addrKoOld" class="form-control" id="addrKoOld">
								</div>
								<div class="form-group">
									<label for="addrEn">영문주소</label> <input type="text"
										name="addrEn" class="form-control" id="addrEn" placeholder="대문자로 입력" required>
								</div>
								<div class="form-group  float-right">
									<button class="btn btn-outline-secondary mr-2" data-toggle="modal"
										data-target="#branch-location">위치찾기</button>
								<button type="submit" class="btn btn-primary">등록</button>
								</div>
							</form>
						</div>
					</div>
					<!-- /.card-body -->
				</div>
				<!-- /.col-12 -->
			</div>
			<!-- .row -->
		</main>
	</div>
	<!-- main -->
	<!-- .wrapper -->

	<div class="modal fade" id="branch-location" role="dialog"
		aria-labelledby="introHeader" aria-hidden="true" tabindex="-1">
		<div class="modal-dialog">
			<div class="modal-content">
				<div class="modal-header">
					<h4 class="modal-title">지점 위치검색</h4>
				</div>
				<div class="modal-body  align-items-center justify-content-center ">
					<div class="col-md-12">
					<div class="form-row mb-4">
						<form class="form-inline">
							<div class="form-group">
								<div class="input-group">
									<input type="text" class="form-control" id="address"
										placeholder="검색할 주소를 입력하세요.">
								</div>
								<!-- /input-group -->
							</div>
							<span class="input-group-btn"><button
									class="btn btn-default" type="button" id="find-location">검색</button>
<!-- 									onclick="javascript:findLocation(); return false;">검색</button> -->
							</span>
						</form></div>
						<div class="align-items-center justify-content-center mb-4" id="map" style="width: 100%; height: 350px;"></div>
						<div class="align-items-center justify-content-center  float-right">
							<button class="btn btn-primary" onclick="fillAddress()" data-dismiss="modal">등록</button>
						</div>
					</div>
				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-default" data-dismiss="modal">취소</button>
				</div>
			</div>
		</div>
	</div>

	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- End Footer -->
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
	<script type="text/javascript"
		src="//dapi.kakao.com/v2/maps/sdk.js?appkey=<spring:eval expression="@property['kakaoJavaScriptKey']"></spring:eval>&libraries=services"></script>

	<script>
		let selectedLoc='';
	
		var mapContainer = document.getElementById('map'), // 지도를 표시할 div 
		
		mapOption = {
			center : new kakao.maps.LatLng(35.233562, 128.881305),
			level : 3,
			mapTypeId : kakao.maps.MapTypeId.ROADMAP
		};

		// 지도를 생성합니다    
		var map = new kakao.maps.Map(mapContainer, mapOption);

		// 주소-좌표 변환 객체를 생성합니다
		var geocoder = new kakao.maps.services.Geocoder();			
		
		
		$("#find-location").click(function(){
			
			let location = $('#address').val();
			
			// 주소로 좌표를 검색합니다
			geocoder.addressSearch(
					location, function(result, status) {

							// 정상적으로 검색이 완료됐으면 
							if (status === kakao.maps.services.Status.OK) {
								var coords = new kakao.maps.LatLng(result[0].y, result[0].x);
								
//								console.log("coords: " + coords)
								selectedLoc = coords;
								
								// 결과값으로 받은 위치를 마커로 표시합니다
								var marker = new kakao.maps.Marker({
								map : map,
								position : coords
							});

							// 지도의 중심을 결과값으로 받은 위치로 이동시킵니다
							map.setCenter(coords);
									
							// 지도크기 동적변화
							map.relayout();
						}
					});
			
		});	
	</script>
	<script>
	function fillAddress() {		
		let loc = selectedLoc;	
	}	
	</script>
	<script>
	
	
	</script>

</body>
</html>