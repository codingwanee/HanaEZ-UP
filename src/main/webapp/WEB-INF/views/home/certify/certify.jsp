<%@ page language="java" contentType="text/html; charset=UTF-8"
pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<!-- ======= Header ======= -->
<!DOCTYPE html>
<html>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<style>
    /* Style the form */

    /* Style the input fields */
    input {
        padding: 10px;
        width: 100%;
        font-size: 17px;
        font-family: Raleway;
        border: 1px solid #aaaaaa;
    }

    /* Mark input boxes that gets an error on validation: */
    input.invalid {
        background-color: #ffdddd;
    
    /* Hide all steps by default: */
    .tab {
        display: none;
    }

    /* Make circles that indicate the steps of the form: */
    .step {
        height: 15px;
        width: 15px;
        margin: 0 2px;
        background-color: #aa0000;
/*         background-color: #bbbbbb; */
        border: none;
        border-radius: 50%;
        display: inline-block;
        opacity: 0.5;
    }

    /* Mark the active step: */
    .step.active {
        opacity: 1;
    }

    /* Mark the steps that are finished and valid: */
    .step.finish {
        background-color: #00aaaa;
/*         background-color: #4CAF50; */
    }
</style>

<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<link
        href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
        rel="icon">

<!-- Google Fonts -->
<link
        href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
        rel="stylesheet">
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp"/>
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp"/>

</head>
<body>
<!-- ======= Header ======= -->
<jsp:include page="/WEB-INF/views/home/include/header.jsp"/>

	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="branch-search"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title"><spring:message code="certify.title"></spring:message></h2>
					<p class="card-text">
						<spring:message code="certify.text"></spring:message>
					</p>
					<div class="row align-items-center justify-content-center">
						<div class="col-md-12 align-items-center">
							<div class="card shadow">
								<div class="card-body">
									<div class="container">
                                    <div class="row d-flex justify-content-center">
                                        <div class="col-sm-12 p-5">
<!--                                             <form id="regForm" action=""> -->
                                                <!-- One "tab" for each step in the form: -->
                                                <div class="tab">
                                                    <h3 class="mb-3">Step 1 - <spring:message code="certify.val.title"></spring:message></h3>
                                                    <p><spring:message code="certify.val.text"></spring:message><br>
													<!-- 
                                                    <a href="#authmail" data-toggle="modal">
                                                        <button class="btn btn-outline-info"><spring:message code="certify.val.email"></spring:message></button>
                                                    </a>
                                                     -->       
                                                    <div class="row justify-content-center align-items-center">                                              
                                                    <a href="#authsms" data-toggle="modal">
                                                        <button class="btn btn-outline-info"><spring:message code="certify.val.sms"></spring:message></button>
                                                    </a>
                                                    </div>
                                                </div>
                                                <form action="${ pageContext.request.contextPath }/certify"
																	method="post" name="certUpload"
																	enctype="multipart/form-data"> 
                                                <div class="tab">
													<h3 class="mb-3">
														Step 2 - 금융거래사유
													</h3>
													<p>금융거래 목적을 영어 또는 한국어로 명확히 기입해주세요.</p>
												  	<p><input style="min-height:80px;" name="reason" type="text"></p>
<!-- 												  	<p><input style="min-height:80px;" oninput="this.className = ''"></p> -->
													<br>
												</div>
												<div class="tab">
														<h3 class="mb-3">
															Step 3 - <spring:message code="certify.text"></spring:message>
														</h3>
														<p><spring:message code="certify.descript"></spring:message></p>
														<div class="row col-lg-12 d-flex align-items-center justify-content-center">
															<div class="row col-lg-12 d-flex align-items-center justify-content-center">
 																
																	<ul>
																		<li><input type="file" name="regCard"></li>
																		<li>																		 
																		<input type="submit" id="upload-btn"
																			value="<spring:message code="register"></spring:message>"
																			class="btn btn-outline-info w-100" style="margin-left: 0">																		 
<%-- 																		 <button id="upload-btn"><spring:message code="register"></spring:message></button> --%>
																		</li>
																	</ul>
															</div>
														</div>
													</div>								
												</form>
                                                <div class="tab">
                                                    <h3 class="mb-3">Step 4 - Completed!</h3>
													<p class="mb-5">
														<spring:message code="certify.complete.descript"></spring:message>
													</p>
                                                    <div class="row d-flex justify-content-center input-group">
													<div class="list-group mb-5 shadow">
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.certId"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">${certHistoryVO.certId }</p></div>
															</div>
														</div>
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.applicant"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">${certHistoryVO.applicantNm }</p></div>
															</div>
														</div>
														<div class="list-group-item">
															<div class="row align-items-center">
																<div class="col"><strong class="mb-2"><spring:message code="certify.regDate"></spring:message></strong></div>
																<div class="col-auto"><p class="text-muted mb-0">${certHistoryVO.regDate }</p></div>
															</div>
														</div>
													</div>
													<!-- .list-group-item -->
												</div>
                                                </div>


                                                <div class="row align-items-center justify-content-center" style="overflow:auto;">
                                                    <div style="float:right;">
                                                        <button type="button" id="prevBtn" onclick="nextPrev(-1)" class="btn btn-secondary" style="width:100px">
                                                            Previous
                                                        </button>
                                                        <button type="button" id="nextBtn" onclick="nextPrev(1)" class="btn btn-info" style="width:100px">Next
                                                        </button>
                                                    </div>
                                                </div>
                                                <!-- Circles which indicates the steps of the form: -->
                                                <div style="text-align:center;margin-top:40px;">
                                                    <span class="step"></span>
                                                    <span class="step"></span>
                                                    <span class="step"></span>
                                                    <span class="step"></span>
                                                </div>

<!--                                             </form> -->

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

<!-- ======= Footer ======= -->
<footer>
    <%@include file="/WEB-INF/views/home/include/footer.jsp"%>
    <jsp:include page="/WEB-INF/views/home/include/common-js.jsp"/>
</footer>
<jsp:include page="/WEB-INF/views/home/certify/authmodal.jsp"/>

<!-- End Footer -->


<script>
    var currentTab = 0; // Current tab is set to be the first tab (0)
    showTab(currentTab); // Display the current tab

    function showTab(n) {
        // This function will display the specified tab of the form ...
        var x = document.getElementsByClassName("tab");
        x[n].style.display = "block";
        // ... and fix the Previous/Next buttons:
        if (n == 0) {
            document.getElementById("prevBtn").style.display = "none";
        } else {
            document.getElementById("prevBtn").style.display = "inline";
        }
        if (n == (x.length - 1)) {
            document.getElementById("nextBtn").innerHTML = "Submit";
        } else {
            document.getElementById("nextBtn").innerHTML = "Next";
        }
        // ... and run a function that displays the correct step indicator:
        fixStepIndicator(n)
    }

    function nextPrev(n) {
        // This function will figure out which tab to display
        var x = document.getElementsByClassName("tab");
        // Exit the function if any field in the current tab is invalid:
        if (n == 1 && !validateForm()) return false;
        // Hide the current tab:
        x[currentTab].style.display = "none";
        // Increase or decrease the current tab by 1:
        currentTab = currentTab + n;
        // if you have reached the end of the form... :
        if (currentTab >= x.length) {
            //...the form gets submitted:
            document.getElementById("regForm").submit();
            return false;
        }
        // Otherwise, display the correct tab:
        showTab(currentTab);
    }

    function validateForm() {
        // This function deals with validation of the form fields
        var x, y, i, valid = true;
        x = document.getElementsByClassName("tab");
        y = x[currentTab].getElementsByTagName("input");
        // A loop that checks every input field in the current tab:
        for (i = 0; i < y.length; i++) {
            // If a field is empty...
            if (y[i].value == "") {
                // add an "invalid" class to the field:
                y[i].className += " invalid";
                // and set the current valid status to false:
                valid = false;
            }
        }
        // If the valid status is true, mark the step as finished and valid:
        if (valid) {
            document.getElementsByClassName("step")[currentTab].className += " finish";
        }
        return valid; // return the valid status
    }

    function fixStepIndicator(n) {
        // This function removes the "active" class of all steps...
        var i, x = document.getElementsByClassName("step");
        for (i = 0; i < x.length; i++) {
            x[i].className = x[i].className.replace(" active", "");
        }
        //... and adds the "active" class to the current step:
        x[n].className += " active";
    }
</script>
<script>
		function doRegister() {
			//파일 확장자 체크
			if (checkExt(f.attachfile1)) {
				return false; // 확장자 위배시 바로 false 리턴하며 doWrite 메소드 종료
			}
			if (checkExt(f.attachfile2)) {
				return false;
			}
			return true;
		}

		function checkExt(obj) {
			let needed = [ 'jpg', 'png', 'gif' ];
			let fileName = obj.value;
			let ext = fileName.substring(fileName.lastIndexOf('.') + 1);

			for (let i = 0; i < needed.length; i++) {
				if (needed != ext) {
					alert('이미지 파일만 업로드할 수 있습니다.<br>(가능 확장자:jpg, png, gif)');
					return true;
				}
			}
			return false;
		}
</script>
<!--
<script>
$(function() {
	$("#upload-btn").on("click", function(){
		var form = new FormData(document.getElementById('uploadForm'));

		function uploadFile() {
			$.ajax({
				url : '${ pageContext.request.contextPath }/certify',
				data : form,
				datatype: 'json',
				processData: false,
				contentType: false,
				type: 'POST',
				success : function(data) {
					alert('파일 업로드 성공')
				},
				error : function() {
					alert('파일 업로드 과정에서 에러가 발생했습니다.')
				}
			})
		}
}}
</script>
-->


</body>
</html>