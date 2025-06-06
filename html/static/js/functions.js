
function set_hosts(selected)
{
  $.ajax({
        url: script_root + '/hosts/',
        type: 'POST',
        data:  JSON.stringify({'selected': selected} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#host_selector').html(res.html);
    });
}


function set_ip_click_handler() {
    $(".ip_addr").unbind("click");
    $(".ip_addr").click(function(event) {
        var ip_address = $(this).attr('data-content') ;
        $("#dns_popup_content").text("");
        $("#passive_dns_data").text("");
        $("#threat_links").text("");
        $("#asn_data").text("");
        $("#whois_data").text("");
        $("#dns_popup").modal('show');

        $.ajax({
            url: script_root +"/reverse_dns/"+ encodeURIComponent(ip_address),
            type: "GET"
        }).done(function(data) {
            var res = JSON.parse(data);
            if (res.success == true) {
                $("#dns_popup_content").html(res.rhtml);
                $("#dns_popup").modal("handleUpdate");
            }
        });
        $.ajax({
            url: script_root +"/whois/"+ encodeURIComponent(ip_address) ,
            type: "GET"
        }).done(function(data) {
            var res = JSON.parse(data);
            if (res.success == true) {
                $("#whois_data").html(res.rhtml);
            }
        });
        $.ajax({
            url: script_root +"/passive_dns/"+ encodeURIComponent(ip_address) ,
            type: "GET"
        }).done(function(data) {
            var res = JSON.parse(data);
            if (res.success == true) {
                $("#passive_dns_data").html(res.rhtml);
            }
        });
        $.ajax({
            url: script_root +"/asn/"+ encodeURIComponent(ip_address) ,
            type: "GET"
        }).done(function(data) {
            var res = JSON.parse(data);
            if (res.success == true) {
                $("#asn_data").html(res.rhtml);
            }
        });
        $.ajax({
            url: script_root +"/threat_links/"+ encodeURIComponent(ip_address) ,
            type: "GET"
        }).done(function(data) {
            var res = JSON.parse(data);
            if (res.success == true) {
                $("#threat_links").html(res.rhtml);
            }
        });
    })
}

function get_period()
{
    var to = null;
    var from = null;
    var period = 'today'
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#24hour").is(":checked")) {period = '24hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    else if ($("#custom").is(":checked")) {
        period = 'custom';
        from = $("#from_date").val();
        to = $("#to_date").val();
    }
    return {period, from, to}
}


