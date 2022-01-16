"use strict";

var colours = [
    '#d43d51',
    '#dd584a',
    '#e27147',
    '#e48948',
    '#bdc367',
    '#e4a04e',
    '#e3b75a',
    '#e0cd6d',
    '#9bb965',
    '#7aae65',
    '#5aa267',
    '#38956a',
    '#00876c',
];

var g_name= '';
var g_type = '';
var g_search = '';
var max_datapoints = 120;

var simple_types = [
    "ssh_users",
    "ssh_ips",
    "apache_response",
    "apache_ips",
];

function round(nr, dig)
{
    if (dig == undefined) dig = 0
    var exp = 10 ** dig;
    return Math.round((nr+ Number.EPSILON) * exp)/exp;
}


function calculate_height()
{
    var nb_height = $("#navbar").height();
    var b_height = $("body").height();
    var w_height = window.innerHeight;
    var res_height = Math.floor(w_height-nb_height);
    $('#maindiv').height(res_height);
}


function fmtChartJSPerso(n, p, fmt)
{
    if (fmt == "text") {
        if (p.length > 15) {
            var s =p;
            var l =p.length;
            return s.slice(0, 5) + "..." + s.slice(l-5, l);
        }
        return p;
    } else if (fmt == 'number') {
        if (p < 10) return round(p, 2).toString();
        if (p < 100) return round(p, 1).toString();
        if (p < 1024) return p;
        if (p < 1024 * 1024 ) return (round(p / 1024, 1)).toString() + "K";
        if (p < 1024 * 1024 * 1024 ) return (round(p / (1024 * 1024), 1)).toString() + "M";
        if (p < 1024 * 1024  * 1024 * 1024 ) return  (round(p / (1024 * 1024 * 1024), 1 )).toString() + "G";
        if (p < 1024 * 1024  * 1024 * 1024  * 1024) return  (round(p / (1024 * 1024 * 1024  * 1024),1)).toString() + "T";
        return p;
    }
}

function load_graph(canvas_id, type, name, period, to,from, title, host)
{
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'type': type, 'period': period, 'name': name, 'raw': true, 'to': to, 'from':from, 'host': host} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        var baroptions= {
            graphTitle: title,
            graphTitleFontSize: 16,
            canvasBorders: true,
            canvasBordersWidth: 1,
            animation : false,
            responsive: true,
            legend: false,
            highLight: true,
            fmtXLabel: "text",
            fmtYLabel: "number",
            rotateLabels: "smart",
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            yAxisUnitFontSize: 16,
            inGraphDataShow : true,
            spaceBetweenBar : 4,
            scaleFontColor: "#ddd",
            graphTitleFontColor: "#bbb",
            inGraphDataFontColor:"#ccc",
            forceScale:"steps",
            scaleSteps : 10,
        };
        var pieoptions = baroptions;
        var stacked_baroptions= {
            graphTitle: title,
            graphTitleFontSize: 16,
            canvasBorders: true,
            canvasBordersWidth: 1,
            barDatasetSpacing: 0,
            barValueSpacing:0,
            rotateLabels: "smart",
            spaceBetweenBar : 4,
            animation : false,
            responsive: true,
            legend: false,
            highLight: true,
            xScaleLabelsMinimumWidth: 10,
            fmtXLabel: "text",
            fmtYLabel: "number",
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            inGraphDataShow : true,
            inGraphDataFontColor: "#ccc",
            yAxisMinimumInterval:1,
            forceGraphMin : 0,
            graphMin:0,
            forceScale:"steps",
            scaleSteps : 10,
            scaleStepWidth : 1,
            yAxisUnitFontSize: 16,
            scaleFontColor: "#ddd",
            graphTitleFontColor: "#bbb",
        };
        if (res.labels.length == 0 || res.data.length == 0) {
        // for an empty graph
            var data_sets = {
                labels : [''],
                datasets: [{ data: [0]}]
            }
            new Chart(document.getElementById(canvas_id).getContext("2d")).Pie(data_sets, pieoptions);
        } else {
            var data_sets = [];
            for (var i = 0; i < res.data.length; i++) {
                data_sets.push( {
                    fillColor: colours[i % colours.length],
                    strokeColor: colours[i % colours.length],
                    data: res.data[i],
                    title: res.labels[i]
                });
            }
            var data = {
                labels: res.fields,
                datasets: data_sets
            }
            if (res.data.length == 1) {
                 baroptions.annotateLabel = "<%=v2+': '+v3%>"
                 if (data.datasets[0].data.length > 10) {
                     baroptions['inGraphDataShow'] = false;
                 }
                 new Chart(document.getElementById(canvas_id).getContext("2d")).Bar(data, baroptions);
            } else {
                 if (data.datasets.length > 10) {
                     stacked_baroptions['inGraphDataShow'] = false;
                 }
                 new Chart(document.getElementById(canvas_id).getContext("2d")).StackedBar(data, stacked_baroptions);
            }
        }
    });
    return false;
}

function get_period()
{
    var to = null;
    var from = null;
    var period = 'today';
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


function load_all_graphs()
{
    var host = $("#host_selector").find(":selected").val()
    let {period, from, to} = get_period()
    $("canvas").each(function() {
        var checkbox_index = $(this).attr('data-type') + "_" + $(this).attr('data-name');
        var checkbox_val= $("#checkbox_" + checkbox_index)[0].checked;
        var canvas_id = $(this).attr('id');
        if (checkbox_val) {
            load_graph(canvas_id, $(this).attr("data-type"), $(this).attr("data-name"), period, to, from,
                       $(this).attr("data-title"), host);
        } else {
            $("#"+canvas_id).parent("div").hide();
        }
    });
}


$( document ).ready(function() {
    set_hosts()
    $('.dropdown-toggle').dropdown()
    $('body').css('background-image', 'url("' + script_root + '/static/img/necronomicon.png")');
    $('body').css('background-size', 'contain');
    $('body').css('opacity', '1.6');
    $("#custom").click(function() {
        $("#custom").prop("checked", true);
     });

    $("[name^='timeperiod").click(function(event) {
       load_all_graphs();
    });
    calculate_height();

    $("#submit_custom").click(function() {
        $("#custom").prop("checked", true);
        $('#custom').dropdown('toggle');
        load_all_graphs();
    });

    $("#host_selector").change(function() { load_all_graphs(); })
    $('#itemstablediv').scrollTop(0);

    $("[id^='checkbox_'").click(function(event) {
        var value = $(this)[0].checked;
        var this_id = $(this).attr('id');
        $.ajax({
            url: script_root + '/set_item/',
            type: 'PUT',
            data:  JSON.stringify({ item: $(this).attr('name') , value: value} ),
            contentType: "application/json;charset=UTF-8",
            cache: false
        }).done(function() {
            var name = $("#"+ this_id)[0].name;
            var checkbox_val= $("#"+ this_id)[0].checked;
            if (checkbox_val) {
                var host = $("#host_selector").find(":selected").val();
                let {period, from, to} = get_period();
                load_graph($("#canvas_" + name).attr('id'), $("#canvas_" + name).attr("data-type"),
                           $("#canvas_" + name).attr("data-name"), period, to, from,
                           $("#canvas_" + name).attr("data-title"), host);
                $("#canvas_div_" + name).show();
            } else {
                $("#canvas_div_" + name).hide();
            }
        });
    });
    $("#compact_button").click(function() {
        $("#left_menu").toggle();
        $("#left_button").toggle();
        $("#right_button").toggle();
    })
    if ($(window).width() < 768) {
        $("#left_menu").hide();
        $("#left_button").hide();
        $("#right_button").show();
    }

    load_all_graphs();
});