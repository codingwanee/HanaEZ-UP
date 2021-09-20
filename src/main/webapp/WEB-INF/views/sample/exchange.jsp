<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
	<title>LOANS2GO | Loans HTML Template</title>
	<meta charset="UTF-8">
	<meta name="description" content="loans HTML Template">
	<meta name="keywords" content="loans, html">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	
	<!-- Favicon -->
	<link href="resources/loan2go/img/favicon.ico" rel="shortcut icon"/>

	<!-- Google font -->
	<link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i,800,800i&display=swap" rel="stylesheet">
 
	<!-- Stylesheets -->
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/bootstrap.min.css"/>
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/font-awesome.min.css"/>
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/owl.carousel.min.css"/>
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/flaticon.css"/>
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/slicknav.min.css"/>

	<!-- Main Stylesheets -->
	<link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/loan2go/css/style.css"/>


	<!--[if lt IE 9]>
		<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
		<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
	<![endif]-->

</head>
<body>
	<!-- Page Preloder -->
	<div id="preloder">
		<div class="loader"></div>
	</div>
 <!-- /////////////// 환율검색 //////////////////// -->

	<!-- Loans calculator Section  -->
	<section class="loans-calculator-section spad">
		<div class="container">
			<div class="text-center text-white mb-5 pb-3">
				<h2>How much do you want to borrow?</h2>
			</div>
			<div class="loans-calculator">
				<div id="lc-dec" class="lc-control-btn">-</div>
				<div id="lc-inc" class="lc-control-btn ici">+</div>
				<div class="slider-input-warp">
					<div id="slider-range-max" class="slider">
						<div class="ui-slider-handle"><span id="loan-value">$1000</span></div>
					</div>
				</div>
				<div class="calculator-scale">
					<span></span>
					<span></span>
					<span></span>
					<span></span>
					<span></span>
				</div>
				<div class="lone-values">
					<div class="lone-value">$1000</div>
					<div class="lone-value lv-step">$10.000</div>
				</div>
				<div class="ls-result">Weekly payments: <span id="lone-emi">$19</span></div>
				<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tem por incididunt ut labore et dolore mag na aliqua.  Class aptent taciti sociosqu ad litora torquent per conubia sed do eiusmod tem por incididun.</p>
				<div class="text-center">
					<a href="#" class="site-btn mr-0 mr-sm-2 mt-4">apply right now!</a>
					<a href="#" class="site-btn sb-dark mt-4">see other loans</a>
				</div>
			</div>
		</div>
	</section>
	<!-- Loans calculator Section end -->

	<!--====== Javascripts & Jquery ======-->
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/jquery-3.2.1.min.js"></script>
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/bootstrap.min.js"></script>
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/jquery.slicknav.min.js"></script>
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/owl.carousel.min.js"></script>
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/jquery-ui.min.js"></script>
	<script src="${ pageContext.request.contextPath }/resources/loan2go/js/main.js"></script>
</body>
</html>