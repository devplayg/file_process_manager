#!/bin/sh

go build ../generator/generator.go
go build ../calculator/calculator.go
go build ../resmanager/resmanager.go
go build ../agentcollector/agentcollector.go
go build ../classifier/classifier.go
go build ../requester/requester.go
go build ../scheduler/scheduler.go

output=~sniper/mserver/
\cp -f resmanager $output
\cp -f agentcollector $output
\cp -f classifier $output
\cp -f generator $output
\cp -f calculator $output
\cp -f scheduler $output
