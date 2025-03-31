package com.datamasking.controller;

import com.datamasking.model.MaskedData;
import com.datamasking.service.DataMaskingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class DataMaskingController {

    @Autowired
    private DataMaskingService dataMaskingService;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("maskedDataList", dataMaskingService.getAllMaskedData());
        return "index";
    }

    @GetMapping("/mask")
    public String maskForm() {
        return "mask";
    }

    @PostMapping("/mask")
    public String maskData(@RequestParam("data") String data,
                           @RequestParam("key") String key,
                           @RequestParam(value = "saveToDb", required = false) boolean saveToDb,
                           Model model) {

        String maskedData = dataMaskingService.maskData(data, key);
        model.addAttribute("originalData", data);
        model.addAttribute("maskedData", maskedData);

        // Save to database if requested
        if (saveToDb && !maskedData.isEmpty()) {
            MaskedData savedData = dataMaskingService.saveMaskedData(data, maskedData, key);
            model.addAttribute("savedId", savedData.getId());
        }

        return "mask-result";
    }

    @GetMapping("/unmask")
    public String unmaskForm() {
        return "unmask";
    }

    @PostMapping("/unmask")
    public String unmaskData(@RequestParam("maskedData") String maskedData,
                             @RequestParam("key") String key,
                             Model model) {

        String unmaskedData = dataMaskingService.unmaskData(maskedData, key);
        model.addAttribute("maskedData", maskedData);
        model.addAttribute("unmaskedData", unmaskedData);

        return "unmask-result";
    }

    @GetMapping("/partial")
    public String partialMaskForm() {
        return "partial";
    }

    @PostMapping("/partial")
    public String partialMask(@RequestParam("maskedData") String maskedData,
                              @RequestParam("key") String key,
                              @RequestParam("pattern") String pattern,
                              Model model) {

        // First decrypt, then apply partial masking
        String decryptedData = dataMaskingService.unmaskData(maskedData, key);
        String partiallyMaskedData = "";

        // Only apply partial masking if decryption was successful
        if (!decryptedData.startsWith("Error:")) {
            partiallyMaskedData = dataMaskingService.applyPartialMasking(decryptedData, pattern);
        } else {
            partiallyMaskedData = decryptedData; // Pass through the error
        }

        model.addAttribute("maskedData", maskedData);
        model.addAttribute("decryptedData", decryptedData);
        model.addAttribute("partiallyMaskedData", partiallyMaskedData);
        model.addAttribute("pattern", pattern);

        return "partial-result";
    }

    @GetMapping("/view/{id}")
    public String viewMaskedData(@PathVariable("id") Long id, Model model) {
        MaskedData maskedData = dataMaskingService.getMaskedDataById(id);
        if (maskedData != null) {
            model.addAttribute("maskedData", maskedData);
            return "view";
        } else {
            return "redirect:/";
        }
    }
}

