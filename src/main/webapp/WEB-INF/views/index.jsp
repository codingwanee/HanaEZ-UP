<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<meta content="" name="descriptison">
<meta content="" name="keywords">
<script src="http://code.jquery.com/jquery-3.5.1.min.js" ></script>

<!-- Favicons -->
<link href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png" rel="icon">

<!-- Google Fonts -->
<link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i" rel="stylesheet">

<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />

</head>

<body class="bg-white">

<!-- ======= Header ======= -->
<jsp:include page="/WEB-INF/views/home/include/header.jsp"/>

<div id="wrapper">
<!-- ======= Hero Section ======= -->
<section id="hero" class="d-flex align-items-center">
	<div class="container">
		<div class="row">
				<div class="col-lg-6 mt-5 pt-5 pt-lg-0 order-2 order-lg-1" data-aos="fade-up" data-aos-delay="100">
					<h1 style="font-family:hanaM !important;">
						<spring:message code="text.main.l"></spring:message>
					</h1>
					<h2 style="font-family:hanaUL !important;">
						<spring:message code="text.main.s"></spring:message>
					</h2>
					<a href="${ pageContext.request.contextPath }/join"	class="btn-get-started scrollto">
						<spring:message code="member.join"></spring:message>
					</a>
				</div>
				<div class="col-lg-6 order-1 order-lg-2 hero-img" >
				<img
					src="${ pageContext.request.contextPath }/resources/assets/img/asset-img.png"
					class="img-fluid animated" alt="main-fluid-img" style="width: 100%">
				</div>
		</div>
	</div>

</section>
<!-- End Hero -->

<main id="main">
	<!-- ======= About Section ======= -->
	<section id="about" class="about">
		<div class="container" style="font-family:hanaM">
			<div class="row justify-content-between">
				<div
					class="col-lg-5 d-flex align-items-center justify-content-center about-img">
					<img src="${ pageContext.request.contextPath }/resources/assets/img/schedule-img.svg"
						class="img-fluid aos-init aos-animate" data-aos="zoom-in">
				</div>
				<div class="col-lg-6 pt-5 pt-lg-0">
					<h3 class="mb-3" data-aos="fade-up" data-aos-delay="100"><spring:message code="text.schedule.head"></spring:message></h3>
					<p data-aos="fade-up" data-aos-delay="100">
						<spring:message code="text.schedule.body"></spring:message>
					</p>
					<div class="row">
						<div class="col-md-6" data-aos="fade-up" data-aos-delay="100">
							<i class="bx bx-calendar"></i>
							<h4><spring:message code="text.schedule.left.head"></spring:message></h4>
							<p><spring:message code="text.schedule.left.body"></spring:message></p>
						</div>
						<div class="col-md-6" data-aos="fade-up" data-aos-delay="200">
							<i class="bx bx-check"></i>
							<h4><spring:message code="text.schedule.right.head"></spring:message></h4>
							<p><spring:message code="text.schedule.right.body"></spring:message></p>
						</div>
					</div>
					<div class="row align-items-center justify-content-center">
					<a href="${ pageContext.request.contextPath }/branch"><button class="btn" style="background-color:#005AC4; color:#fff">???????????? ????????????</button></a>
					</div>
				</div>
			</div>
		</div>
	</section>
	<!-- End About Section -->
	
	
			<!-- ======= Services Section ======= -->
	<section id="services" class="services section-bg">
		<div class="container">
			<div class="section-title" data-aos="fade-up">
				<h2>Services</h2>
				<p><spring:message code="service.text"></spring:message></p>
			</div>

			<div class="row">
				<div class="col-md-6 col-lg-3 d-flex align-items-stretch"
					data-aos="zoom-in" data-aos-delay="100">
					<div class="icon-box">
						<div class="icon">
							<i class="bx bx-dollar"></i>
						</div>
						<h4 class="title">
							<a href=""><spring:message code="certify.title"></spring:message></a>
<%-- 							<a href=""><spring:message code="menu.transfer"></spring:message></a> --%>
						</h4>
						<p class="description">?????? ????????? ????????? ???????????? ?????? ???????????? ????????? ??????????????? ???????????????.</p>
					</div>
				</div>

				<div class="col-md-6 col-lg-3 d-flex align-items-stretch"
					data-aos="zoom-in" data-aos-delay="200">
					<div class="icon-box">
						<div class="icon">
							<i class="bx bx-file"></i>
						</div>
						<h4 class="title">
							<a href=""><spring:message code="menu.account"></spring:message></a>
						</h4>
						<p class="description">????????? ????????? ?????? ?????? ??????! Easy One Pack ??????, ?????? ????????? ???????????????.</p>
					</div>
				</div>

				<div class="col-md-6 col-lg-3 d-flex align-items-stretch"
					data-aos="zoom-in" data-aos-delay="300">
					<div class="icon-box">
						<div class="icon">
							<i class="bx bx-world"></i>
						</div>
						<h4 class="title">
							<a href=""><spring:message code="menu.global"></spring:message></a>
						</h4>
						<p class="description">??????????????? ????????? ????????? ?????? 16?????? ????????? ???????????????.</p>
					</div>
				</div>

				<div class="col-md-6 col-lg-3 d-flex align-items-stretch"
					data-aos="zoom-in" data-aos-delay="400">
					<div class="icon-box">
						<div class="icon">
							<i class="bx bx-chat"></i> 
						</div>
						<h4 class="title">
							<a href=""><spring:message code="menu.translator"></spring:message></a>
						</h4>
						<p class="description">????????? ??? ????????? ?????? ????????? ?????? ?????????? ???????????? ???????????? ??? ?????? HanaEZ UP?????? ???????????????. </p>
					</div>
				</div>

			</div>

		</div>
	</section>
	<!-- End Services Section -->

	<!-- ======= Portfolio Section ======= -->
	<section id="portfolio" class="portfolio">
		<div class="container">
			<div class="section-title" data-aos="fade-up">
				<h2>Branches</h2>
				<p><spring:message code="section.branches.title"></spring:message></p>
			</div>

			<div class="row" data-aos="fade-up" data-aos-delay="100">
				<div class="col-lg-12">
					<ul id="portfolio-flters">
						<li data-filter="*" class="filter-active">All</li>
						<li data-filter=".filter-app">App</li>
						<li data-filter=".filter-card">Card</li>
						<li data-filter=".filter-web">Web</li>
					</ul>
				</div>
			</div>

			<div class="row portfolio-container" data-aos="fade-up"
				data-aos-delay="200">

				<div class="col-lg-4 col-md-6 portfolio-item filter-app">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a1.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a1.jpg"
								data-gall="portfolioGallery" class="venobox" title="App 1"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>App 1</h4>
							<p>App</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-web">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a2.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a2.jpg"
								data-gall="portfolioGallery" class="venobox" title="Web 3"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>Web 3</h4>
							<p>Web</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-app">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a3.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a3.jpg"
								data-gall="portfolioGallery" class="venobox" title="App 2"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>App 2</h4>
							<p>App</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-card">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a4.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a4.jpg"
								data-gall="portfolioGallery" class="venobox" title="Card 2"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>Card 2</h4>
							<p>Card</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-web">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a5.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a5.jpg"
								data-gall="portfolioGallery" class="venobox" title="Web 2"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>Web 2</h4>
							<p>Web</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-app">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/a6.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a6.jpg"
								data-gall="portfolioGallery" class="venobox" title="App 3"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>App 3</h4>
							<p>App</p>
						</div>
					</div>
				</div>

	<div class="col-lg-4 col-md-6 portfolio-item filter-app">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/b1.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a1.jpg"
								data-gall="portfolioGallery" class="venobox" title="App 1"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>App 1</h4>
							<p>App</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-web">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/b2.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a2.jpg"
								data-gall="portfolioGallery" class="venobox" title="Web 3"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>Web 3</h4>
							<p>Web</p>
						</div>
					</div>
				</div>

				<div class="col-lg-4 col-md-6 portfolio-item filter-app">
					<div class="portfolio-wrap">
						<img src="${ pageContext.request.contextPath }/resources/images/branches/b3.jpg" class="img-fluid"
							alt="">
						<div class="portfolio-links">
							<a href="${ pageContext.request.contextPath }/resources/images/branches/a3.jpg"
								data-gall="portfolioGallery" class="venobox" title="App 2"><i
								class="icofont-plus-circle"></i></a> <a href="#"
								title="More Details"><i class="icofont-link"></i></a>
						</div>
						<div class="portfolio-info">
							<h4>App 2</h4>
							<p>App</p>
						</div>
					</div>
				</div>

			</div>

		</div>
	</section>
	<!-- End Portfolio Section -->

	<!-- ======= F.A.Q Section ======= -->
	<section id="faq" class="faq section-bg">
		<div class="container">

			<div class="section-title" data-aos="fade-up">
				<h2>F.A.Q</h2>
				<p><spring:message code="menu.faq"></spring:message></p>
			</div>

			<ul class="faq-list">

				<li data-aos="fade-up" data-aos-delay="100"><a
					data-toggle="collapse" class="" href="#faq1">???????????? ??? ????????? ???????????? ????????? ????????? ??? ??????????<i class="icofont-simple-up"></i>
				</a>
					<div id="faq1" class="collapse show" data-parent=".faq-list">
						<p>?????????????????????  HanaEZ UP??? ?????? 2020????????? ????????? ??????????????? ????????? ???????????? ???????????? ???????????? ????????????.</p>
					</div></li>

				<li data-aos="fade-up" data-aos-delay="200"><a
					data-toggle="collapse" href="#faq2" class="collapsed">????????? ??????????????? ?????? ????????????! ???????????? ??? ????????? ??????????<i
						class="icofont-simple-up"></i>
				</a>
					<div id="faq2" class="collapse" data-parent=".faq-list">
						<p>??????????????????(???) ?????? ????????? ??????(???) ?????? ????????? ?????? ??????????????? ???????????????, ???????????? ?????? ????????? ??? ????????????.</p>
					</div></li>

				<li data-aos="fade-up" data-aos-delay="300"><a
					data-toggle="collapse" href="#faq3" class="collapsed">????????? ???????????? ?????????, ???????????? ?????? ?????? ????????? ?????????????<i
						class="icofont-simple-up"></i>
				</a>
					<div id="faq3" class="collapse" data-parent=".faq-list">
						<p>????????????????????? ?????? 14?????? ????????? ?????? ????????? ???????????? ????????????. ????????? 10~6?????? ???????????? ?????? ???????????? ????????? ??? ?????????, HanaEZ UP?????? ??????????????? ??? ??? ????????????.</p>
					</div></li>

				<li data-aos="fade-up" data-aos-delay="400"><a
					data-toggle="collapse" href="#faq4" class="collapsed">
					????????? ?????? ???????????? ???????????? ???????????? ????????????. ????????? ??? ?????? ????????? ??????????
					<i class="icofont-simple-up"></i>
				</a>
					<div id="faq4" class="collapse" data-parent=".faq-list">
						<p>HanaEZ UP????????? ????????? ???????????? ???????????? ???????????? ????????????. ???????????? ?????? ???????????? ??????????????? ???????????????, ?????? ??? ?????????????????? ???????????????.</p>
					</div></li>

				<li data-aos="fade-up" data-aos-delay="500"><a
					data-toggle="collapse" href="#faq5" class="collapsed">???????????? ?????? ???????????? ?????? ????????? ????????? ??? ??????????<i
						class="icofont-simple-up"></i>
				</a>
					<div id="faq5" class="collapse" data-parent=".faq-list">
						<p>????????????????????? ????????? ????????? ?????? EasyOne pack????????? ?????? ????????? ????????? ???????????? ????????????.</p>
					</div></li>

				<li data-aos="fade-up" data-aos-delay="600"><a
					data-toggle="collapse" href="#faq6" class="collapsed">HanaEZ UP??? ???????????????! ?????????????????? ?????? ???????????? ?????????? <i class="icofont-simple-up"></i>
				</a>
					<div id="faq6" class="collapse" data-parent=".faq-list">
						<p>HanaEZ UP??? ?????? ??????????????? ?????? ????????? ???????????? ???????????? ???????????? ??? ????????????. ??????????????? ??????????????? ???????????? ?????? ???????????? ?????? ???????????? ???????????? ??? ????????????.</p>
					</div></li>

			</ul>

		</div>
	</section>
	<!-- End F.A.Q Section -->

	<!-- ======= Team Section ======= -->
<!--  
	<section id="team" class="team">
		<div class="container">

			<div class="section-title" data-aos="fade-up">
				<h2>Team</h2>
				<p>Our team is always here to help</p>
			</div>

			<div class="row">

				<div class="col-xl-3 col-lg-4 col-md-6" data-aos="zoom-in"
					data-aos-delay="100">
					<div class="member">
						<img src="${ pageContext.request.contextPath }/resources/assets/img/team/team-1.jpg" class="img-fluid" alt="">
						<div class="member-info">
							<div class="member-info-content">
								<h4>Walter White</h4>
								<span>Chief Executive Officer</span>
							</div>
							<div class="social">
								<a href=""><i class="icofont-twitter"></i></a> <a href=""><i
									class="icofont-facebook"></i></a> <a href=""><i
									class="icofont-instagram"></i></a> <a href=""><i
									class="icofont-linkedin"></i></a>
							</div>
						</div>
					</div>
				</div>

				<div class="col-xl-3 col-lg-4 col-md-6" data-aos="zoom-in"
					data-aos-delay="200">
					<div class="member">
						<img src="${ pageContext.request.contextPath }/resources/assets/img/team/team-2.jpg" class="img-fluid" alt="">
						<div class="member-info">
							<div class="member-info-content">
								<h4>Sarah Jhonson</h4>
								<span>Product Manager</span>
							</div>
							<div class="social">
								<a href=""><i class="icofont-twitter"></i></a> <a href=""><i
									class="icofont-facebook"></i></a> <a href=""><i
									class="icofont-instagram"></i></a> <a href=""><i
									class="icofont-linkedin"></i></a>
							</div>
						</div>
					</div>
				</div>

				<div class="col-xl-3 col-lg-4 col-md-6" data-aos="zoom-in"
					data-aos-delay="300">
					<div class="member">
						<img src="${ pageContext.request.contextPath }/resources/assets/img/team/team-3.jpg" class="img-fluid" alt="">
						<div class="member-info">
							<div class="member-info-content">
								<h4>William Anderson</h4>
								<span>CTO</span>
							</div>
							<div class="social">
								<a href=""><i class="icofont-twitter"></i></a> <a href=""><i
									class="icofont-facebook"></i></a> <a href=""><i
									class="icofont-instagram"></i></a> <a href=""><i
									class="icofont-linkedin"></i></a>
							</div>
						</div>
					</div>
				</div>

				<div class="col-xl-3 col-lg-4 col-md-6" data-aos="zoom-in"
					data-aos-delay="400">
					<div class="member">
						<img src="${ pageContext.request.contextPath }/resources/assets/img/team/team-4.jpg" class="img-fluid" alt="">
						<div class="member-info">
							<div class="member-info-content">
								<h4>Amanda Jepson</h4>
								<span>Accountant</span>
							</div>
							<div class="social">
								<a href=""><i class="icofont-twitter"></i></a>
								<a href=""><i class="icofont-facebook"></i></a>
								<a href=""><i class="icofont-instagram"></i></a>
								<a href=""><i class="icofont-linkedin"></i></a>
							</div>
						</div>
					</div>
				</div>

			</div>

		</div>
	</section>
	-->
	<!-- End Team Section -->

	<!-- ======= subsidiary Section ======= -->
	<section id="subsidiary" class="clients">
		<div class="container">

			<div class="section-title" data-aos="fade-up">
				<h2>Hana Families</h2>
				<p>?????????????????? ???????????? ???????????????</p>
			</div>

			<div class="owl-carousel clients-carousel" data-aos="fade-up"
				data-aos-delay="100">
				<img src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-1.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-2.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-3.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-4.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-5.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-6.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-7.png" alt=""> <img
					src="${ pageContext.request.contextPath }/resources/assets/img/clients/client-8.png" alt="">
			</div>

		</div>
	</section>
	<!-- End Clients Section -->

	<!-- ======= Contact Us Section ======= -->
	<!-- 
	<section id="contact" class="contact">
		<div class="container">

			<div class="section-title" data-aos="fade-up">
				<h2>Contact Us</h2>
				<p>Contact us the get started</p>
			</div>

			<div class="row">

				<div class="col-lg-5 d-flex align-items-stretch" data-aos="fade-up"
					data-aos-delay="100">
					<div class="info">
						<div class="address">
							<i class="icofont-google-map"></i>
							<h4>Location:</h4>
							<p>35 Euljiro, Jung-gu, Seoul </p>
						</div>

						<div class="email">
							<i class="icofont-envelope"></i>
							<h4>Email:</h4>
							<p>info@example.com</p>
						</div>

						<div class="phone">
							<i class="icofont-phone"></i>
							<h4>Call:</h4>
							<p>+82 1599-6111<br>(ext. 8 for foreign languages) </p>
						</div>

						<iframe
							src="https://www.google.com/maps/embed?pb=!1m14!1m8!1m3!1d12650.07475780446!2d126.9818843!3d37.5664021!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x0%3A0x4956c89b6420af00!2zS0VC7ZWY64KY7J2A7ZaJIOuzuOygkA!5e0!3m2!1sko!2skr!4v1598584492270!5m2!1sko!2skr"
							frameborder="0" style="border: 0; width: 100%; height: 290px;"
							allowfullscreen></iframe>
					</div>

				</div>

				<div class="col-lg-7 mt-5 mt-lg-0 d-flex align-items-stretch"
					data-aos="fade-up" data-aos-delay="200">
					<form action="forms/contact.php" method="post" role="form"
						class="php-email-form">
						<div class="form-row">
							<div class="form-group col-md-6">
								<label for="name">Your Name</label> <input type="text"
									name="name" class="form-control" id="name" data-rule="minlen:4"
									data-msg="Please enter at least 4 chars" />
								<div class="validate"></div>
							</div>
							<div class="form-group col-md-6">
								<label for="name">Your Email</label> <input type="email"
									class="form-control" name="email" id="email" data-rule="email"
									data-msg="Please enter a valid email" />
								<div class="validate"></div>
							</div>
						</div>
						<div class="form-group">
							<label for="name">Subject</label> <input type="text"
								class="form-control" name="subject" id="subject"
								data-rule="minlen:4"
								data-msg="Please enter at least 8 chars of subject" />
							<div class="validate"></div>
						</div>
						<div class="form-group">
							<label for="name">Message</label>
							<textarea class="form-control" name="message" rows="10"
								data-rule="required" data-msg="Please write something for us"></textarea>
							<div class="validate"></div>
						</div>
						<div class="mb-3">
							<div class="loading">Loading</div>
							<div class="error-message"></div>
							<div class="sent-message">Your message has been sent. Thank
								you!</div>
						</div>
						<div class="text-center">
							<button type="submit">Send Message</button>
						</div>
					</form>
				</div>

			</div>
		</div>
	</section>
	 -->
	<!-- End Contact Us Section -->
</main>
</div>
<!-- End #main -->
	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>
	<!-- End Footer -->
</body>

</html>