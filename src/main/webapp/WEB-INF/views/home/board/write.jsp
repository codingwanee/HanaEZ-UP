<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
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

</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />


	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ======= Board Write Section ======= -->
		<section id="write" class="container">
			<div class="row">
				<div class="col-sm-12">
					<h2 class="page-title"><spring:message code="board.bread.title"></spring:message></h2>
					<p class="card-text"><spring:message code="board.bread.text"></spring:message></p>
					<div class="row mb-4">
						<div class="col-md-10">
							<div class="card shadow">
								<div class="card-body">
									<h5 class="card-title"><spring:message code="board.desc.title"></spring:message></h5>
									<p><spring:message code="board.desc.text"></spring:message>
									</p>
									<form action="${ pageContext.request.contextPath }/board/write" method="post">
									<div class="row writing-header form-group">
										<div class="col-sm-3">
											<select class="form-control writing-category" id="subject-select" name="subject">
												<option selected>말머리</option>
												<option value="정보공유">정보공유</option>
												<option value="질문">질문</option>
												<option value="기타">기타</option>
											</select>
										</div>
										<div class="col-sm-9">
											<input type="text" id="title" name="title"
												class="form-control" placeholder="Input title here">
										</div>
									</div>
<!-- 									<div id="editor" style="min-height: 100px;"
										class="ql-container ql-snow">
										<div class="ql-editor" data-gramm="false"
											contenteditable="true">	</div>
										<div class="ql-clipboard" contenteditable="true" tabindex="-1"></div>
										<div class="ql-tooltip ql-hidden">
											<a class="ql-preview" rel="noopener noreferrer"
												target="_blank" href="about:blank"></a>
												<input type="text" id="content" name="content"
												data-formula="e=mc^2" data-link="https://quilljs.com"
												data-video="Embed URL"><a class="ql-action"></a><a
												class="ql-remove"></a>
										</div>
									</div> -->
									
									<div id="editor" class="">
<!-- 										<input name="content" class="writing-editor" style="height: 300px;">		 -->
										<textarea rows="12" cols="1" class="writing-editor" style="height: 300px;" name="content"></textarea>							
									</div>
									<div class="row">
										<div class="col-sm-12"></div>
										<div class="col-sm-12">
											<div class="row align-items-center justify-content-center">
												<div class="col-sm-2">
													<button type="submit" class="btn btn-info">
														<spring:message code="register"></spring:message>
													</button>
												</div>
											</div>											
										</div>
									</div>
									</form>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
		<!-- end section -->
	</div>

<!--
 	<script>
		// editor
		var editor = document.getElementById('editor');
		if (editor) {
			var toolbarOptions = [ [ {
				'font' : []
			} ], [ {
				'header' : [ 1, 2, 3, 4, 5, 6, false ]
			} ], [ 'bold', 'italic', 'underline', 'strike' ],
					[ 'blockquote', 'code-block' ], [ {
						'header' : 1
					}, {
						'header' : 2
					} ], [ {
						'list' : 'ordered'
					}, {
						'list' : 'bullet'
					} ], [ {
						'script' : 'sub'
					}, {
						'script' : 'super'
					} ], [ {
						'indent' : '-1'
					}, {
						'indent' : '+1'
					} ], // outdent/indent
					[ {
						'direction' : 'rtl'
					} ], // text direction
					[ {
						'color' : []
					}, {
						'background' : []
					} ], // dropdown with defaults from theme
					[ {
						'align' : []
					} ], [ 'clean' ] // remove formatting button
			];
			var quill = new Quill(editor, {
				modules : {
					toolbar : toolbarOptions
				},
				theme : 'snow'
			});
		}
	</script>
	 -->

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>