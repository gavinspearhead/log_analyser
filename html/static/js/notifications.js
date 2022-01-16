
"use strict";

var g_search = '';
var g_type = '';

function handle_request(search, type)
{
    g_search = search;
    g_type = type;
    var host = $("#host_selector").find(":selected").val()
    var period = 'today';
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#24hour").is(":checked")) {period = '24hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    $('#itemstable').html('');
    $.ajax({
        url: script_root + '/notifications_data/',
        type: 'POST',
        data: JSON.stringify({ 'period': period, 'search': search, 'host': host, 'type': type}),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#itemstable').html(res.rhtml);
        document.title = ("Log Analyser - Notifications: " + res.title_type + " " + period).replace("_", " ");
        $("#header").text((res.title_type + ": " + period).replace("_", " "));
        set_ip_click_handler();
    });
    return false;
}


$( document ).ready(function() {
    set_hosts();
    $('body').css('background-image', 'url("' + script_root + '/static/img/necronomicon.png")');
    $('body').css('background-size', 'contain');
    $('#itemstablediv').scrollTop(0);
    $("[data-type^='apache']").click(function(event) { handle_request(  $("#searchbar").val(),'apache') });
    $("[data-type^='ssh']").click(function(event) { handle_request(  $("#searchbar").val(), 'ssh') });
    $("[name^='timeperiod").click(function(event) { handle_request( g_search, g_type); });
    handle_request('', 'ssh');
});